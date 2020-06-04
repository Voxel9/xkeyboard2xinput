#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xboxkrnl/xboxkrnl.h>
#include <winapi/winbase.h>
#include <winapi/winerror.h>
#include <hal/input.h>
#include <xbdm/xbdm.h>

#include "XbSymbolDatabase/XbSymbolDatabase.h"
#include "types.h"

// Scanned addresses are stored here
uint32_t Addr_XInitDevices      = 0;
uint32_t Addr_XGetDevices       = 0;
uint32_t Addr_XGetDeviceChanges = 0;
uint32_t Addr_XInputOpen        = 0;
uint32_t Addr_XInputGetState    = 0;
uint32_t Addr_XInputClose       = 0;

// Check if functions are found, so plugin knows which ones to patch
bool XInitDevices_found      = false;
bool XGetDevices_found       = false;
bool XGetDeviceChanges_found = false;
bool XInputOpen_found        = false;
bool XInputGetState_found    = false;
bool XInputClose_found       = false;

// TODO: Figure out why most games' input freaks out and controls by itself,
// and also why most games frequently lock up, usually while in-game.

VOID WINAPI Hook_XInitDevices(PVOID dwPreallocTypeCount, PVOID PreallocTypes) {
    XInput_Init();
}

DWORD WINAPI Hook_XGetDevices(PVOID DeviceType) {
    // HACK: Make game constantly detect controller in port 1 (might not play nice with input logic)
    return 0b0001;
}

// This one isn't hooked for now. Games/apps crashing instantly for some reason
/* BOOL WINAPI Hook_XGetDeviceChanges(PVOID DeviceType, PDWORD pdwInsertions, PDWORD pdwRemovals) {
    *pdwInsertions = 0b0001;
    *pdwRemovals = 0b0000;
    
    return TRUE;
} */

HANDLE WINAPI Hook_XInputOpen(PVOID DeviceType, DWORD dwPort, DWORD dwSlot, XINPUT_POLLING_PARAMETERS *pPollingParameters) {
    POLLING_PARAMETERS_HANDLE *pph = malloc(sizeof(POLLING_PARAMETERS_HANDLE));
    
    if(pPollingParameters != NULL) {
        pph->pPollingParameters = malloc(sizeof(XINPUT_POLLING_PARAMETERS));
        memcpy(pph->pPollingParameters, pPollingParameters, sizeof(XINPUT_POLLING_PARAMETERS));
    } else {
        pph->pPollingParameters = NULL;
    }
    
    return (HANDLE)pph;
}

// Gamepad state for keyboard input
XINPUT_STATE pad;
XKEYBOARD_STROKE ks;

void process_digital_button(BYTE keycode, DWORD button) {
    if(ks.ucKeyCode == keycode) {
        if (ks.ucFlags & XKEYBOARD_KEYUP) {
            pad.Gamepad.wButtons &= ~button;
        } else {
            pad.Gamepad.wButtons |= button;
        }
    }
}

void process_analog_button(BYTE keycode, BYTE button) {
    if(ks.ucKeyCode == keycode) {
        if (ks.ucFlags & XKEYBOARD_KEYUP) {
            pad.Gamepad.bAnalogButtons[button] = 0x00;
        } else {
            pad.Gamepad.bAnalogButtons[button] = 0xff;
        }
    }
}

void process_axis(SHORT *axis, BYTE keycode, BOOL is_positive) {
    if(ks.ucKeyCode == keycode) {
        if (ks.ucFlags & XKEYBOARD_KEYUP) {
            *axis = 0;
        } else {
            *axis = is_positive ? 32767 : -32768;
        }
    }
}

DWORD WINAPI Hook_XInputGetState(PVOID dwUserIndex, PXINPUT_STATE pState) {
    if(XInputGetKeystroke(&ks) < 0)
        return 0;
    
    if(ks.ucKeyCode == 0)
        return 0;
    
    // System Functions
    if(ks.ucKeyCode == XKEY_ESCAPE) // Quit to dashboard
        exit(0);
    else if(ks.ucKeyCode == XKEY_DELETE) // Reboot xbox
        XReboot();
    
    // Digital Buttons
    process_digital_button(XKEY_I, 0x00000001);
    process_digital_button(XKEY_K, 0x00000002);
    process_digital_button(XKEY_J, 0x00000004);
    process_digital_button(XKEY_L, 0x00000008);
    process_digital_button(XKEY_RETURN, 0x00000010);
    process_digital_button(XKEY_BACKSPACE, 0x00000020);
    process_digital_button(XKEY_R, 0x00000040);
    process_digital_button(XKEY_T, 0x00000080);
    
    // Analog Buttons
    process_analog_button(XKEY_SPACE, 0);
    process_analog_button(XKEY_C, 1);
    process_analog_button(XKEY_Z, 2);
    process_analog_button(XKEY_X, 3);
    process_analog_button(XKEY_3, 4);
    process_analog_button(XKEY_1, 5);
    process_analog_button(XKEY_Q, 6);
    process_analog_button(XKEY_E, 7);
    
    // Thumbstick Axes
    process_axis(&pad.Gamepad.sThumbLY, XKEY_UP, TRUE);
    process_axis(&pad.Gamepad.sThumbLY, XKEY_DOWN, FALSE);
    process_axis(&pad.Gamepad.sThumbLX, XKEY_LEFT, FALSE);
    process_axis(&pad.Gamepad.sThumbLX, XKEY_RIGHT, TRUE);
    
    process_axis(&pad.Gamepad.sThumbRY, XKEY_W, TRUE);
    process_axis(&pad.Gamepad.sThumbRY, XKEY_S, FALSE);
    process_axis(&pad.Gamepad.sThumbRX, XKEY_A, FALSE);
    process_axis(&pad.Gamepad.sThumbRX, XKEY_D, TRUE);
    
    memcpy(pState, &pad, sizeof(XINPUT_STATE));
    
    return 0;
}

VOID WINAPI Hook_XInputClose(HANDLE hDevice) {
    POLLING_PARAMETERS_HANDLE *pph = (POLLING_PARAMETERS_HANDLE*)hDevice;
    
    if(pph->pPollingParameters != NULL) {
        free(pph->pPollingParameters);
    }
    
    free(pph);
}

void scan_for_func(const char *target_str, const char *symbol_str, uint32_t func_addr, uint32_t *store_address, bool *bool_found) {
    if(!*bool_found && !strcmp(target_str, symbol_str)) {
        *store_address = func_addr;
        *bool_found = true;
    }
}

VOID CDECL locate_functions(const char* library_str, uint32_t library_flag, const char* symbol_str, uint32_t func_addr, uint32_t revision) {
    scan_for_func("XInitDevices", symbol_str, func_addr, &Addr_XInitDevices, &XInitDevices_found);
    scan_for_func("XGetDevices", symbol_str, func_addr, &Addr_XGetDevices, &XGetDevices_found);
    // scan_for_func("XGetDeviceChanges", symbol_str, func_addr, &Addr_XGetDeviceChanges, &XGetDeviceChanges_found);
    scan_for_func("XInputOpen", symbol_str, func_addr, &Addr_XInputOpen, &XInputOpen_found);
    scan_for_func("XInputGetState", symbol_str, func_addr, &Addr_XInputGetState, &XInputGetState_found);
    scan_for_func("XInputClose", symbol_str, func_addr, &Addr_XInputClose, &XInputClose_found);
}

void ScanForSymbols() {
    XbSDBLibraryHeader lib_header;
	XbSDBSectionHeader sec_header;
	
	lib_header.count = XbSymbolDatabase_GenerateLibraryFilter((PVOID)0x00010000, NULL);
	sec_header.count = XbSymbolDatabase_GenerateSectionFilter((PVOID)0x00010000, NULL, false);
	
	lib_header.filters = malloc(lib_header.count * sizeof(XbSDBLibrary));
	sec_header.filters = malloc(sec_header.count * sizeof(XbSDBSection));
	
	XbSymbolDatabase_GenerateLibraryFilter((PVOID)0x00010000, &lib_header);
	XbSymbolDatabase_GenerateSectionFilter((PVOID)0x00010000, &sec_header, false);
	
	uint32_t thunk_addr = XbSymbolDatabase_GetKernelThunkAddress((PVOID)0x00010000);
	XbSymbolContextHandle xapi_handle;
	
	if(!XbSymbolDatabase_CreateXbSymbolContext(&xapi_handle, locate_functions, lib_header, sec_header, thunk_addr)) {
		XReboot();
	}
	
	XbSymbolContext_ScanManual(xapi_handle);
	XbSymbolContext_ScanLibrary(xapi_handle, lib_header.filters, true);
	XbSymbolContext_RegisterXRefs(xapi_handle);
	XbSymbolContext_Release(xapi_handle);
	
	free(sec_header.filters);
	free(lib_header.filters);
}

void hook_function(void (*function), uint32_t func_address, bool is_found) {
    if(is_found) {
        BYTE old_bytes[6];
        BYTE jump_hook[6] = {0xE9, 0x90, 0x90, 0x90, 0x90, 0xC3};
        
        memcpy(old_bytes, (PVOID)func_address, 6);
        DWORD jump_size = ((DWORD)function - func_address - 5);
        memcpy(&jump_hook[1], &jump_size, 4);
        memcpy((PVOID)func_address, jump_hook, 6);
    }
}

DWORD NTAPI modload_callback(ULONG Notification, DWORD Parameter) {
    PDMN_MODLOAD Module = (PDMN_MODLOAD)Parameter;
    
    // Early out if this isn't what we wanted
    if (Notification != DM_MODLOAD)
        return 0;
    
    // Early out if no XBE was loaded
    if ((XeImageFileName->Length == 0) || (XeImageFileName->Buffer == NULL))
        return 0;
    
    // First, scan for XInput function locations
    ScanForSymbols();
    
    // Hook XInput functions
    hook_function(Hook_XInitDevices, Addr_XInitDevices, XInitDevices_found);
    hook_function(Hook_XGetDevices, Addr_XGetDevices, XGetDevices_found);
    //hook_function(Hook_XGetDeviceChanges, Addr_XGetDeviceChanges, XGetDeviceChanges_found);
    hook_function(Hook_XInputOpen, Addr_XInputOpen, XInputOpen_found);
    hook_function(Hook_XInputGetState, Addr_XInputGetState, XInputGetState_found);
    hook_function(Hook_XInputClose, Addr_XInputClose, XInputClose_found);
    
    return 0;
}

int main() { (void)KeTickCount; return 0; }

void DxtEntry(ULONG *pfUnload) {
    static PDMN_SESSION DmSession;
    
    HRESULT hr = DmOpenNotificationSession(DM_PERSISTENT, &DmSession);
    
    if(SUCCEEDED(hr))
        hr = DmNotify(DmSession, DM_MODLOAD, modload_callback);
    
    *pfUnload = SUCCEEDED(hr) ? FALSE : TRUE;
}
