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
uint32_t Addr_XInitDevices = 0;
uint32_t Addr_XGetDevices = 0;
uint32_t Addr_XGetDeviceChanges = 0;
uint32_t Addr_XInputOpen = 0;
uint32_t Addr_XInputGetState = 0;
uint32_t Addr_XInputClose = 0;

// Check if functions are found, so plugin knows which ones to patch
bool XInitDevices_found = false;
bool XGetDevices_found = false;
bool XGetDeviceChanges_found = false;
bool XInputOpen_found = false;
bool XInputGetState_found = false;
bool XInputClose_found = false;

VOID WINAPI Hook_XInitDevices(PVOID dwPreallocTypeCount, PVOID PreallocTypes) {
    XInput_Init();
}

DWORD WINAPI Hook_XGetDevices(PVOID DeviceType) {
    // HACK: Make game constantly detect controller in port 1 (might not play nice with input logic)
    return 0b0001;
}

// This one isn't hooked for now. Games/apps crashing instantly for some reason
BOOL WINAPI Hook_XGetDeviceChanges(PVOID DeviceType, PDWORD pdwInsertions, PDWORD pdwRemovals) {
    *pdwInsertions = 0b0001;
    *pdwRemovals = 0b0000;
    
    return TRUE;
}

// Create a dummy handle to make XInputOpen happy
HANDLE xinput_handle;

HANDLE WINAPI Hook_XInputOpen(PVOID DeviceType, PVOID dwPort, PVOID dwSlot, PVOID pPollingParameters) {
    xinput_handle = malloc(4); // Gives return value something not 0 and (hopefully) also won't crash
    return xinput_handle;
}

// Gamepad state for keyboard input
XINPUT_STATE pad;

void process_digital_button(XKEYBOARD_STROKE *ks, DWORD button) {
    if (ks->ucFlags & XKEYBOARD_KEYUP) {
        pad.Gamepad.wButtons &= ~button;
    } else {
        pad.Gamepad.wButtons |= button;
    }
}

void process_analog_button(XKEYBOARD_STROKE *ks, BYTE button) {
    if (ks->ucFlags & XKEYBOARD_KEYUP) {
        pad.Gamepad.bAnalogButtons[button] = 0x00;
    } else {
        pad.Gamepad.bAnalogButtons[button] = 0xff;
    }
}

void process_thumbsticks(XKEYBOARD_STROKE *ks, SHORT *axis, BOOL is_positive) {
    if (ks->ucFlags & XKEYBOARD_KEYUP) {
        *axis = 0;
    } else {
        if(is_positive)
            *axis = 32767;
        else
            *axis = -32768;
    }
}

// TODO: Figure out why most games' input freaks out and controls by itself,
// and also why most games frequently lock up, usually while in-game.

DWORD WINAPI Hook_XInputGetState(PVOID dwUserIndex, PXINPUT_STATE pState) {
    XKEYBOARD_STROKE ks;
    
    if(XInputGetKeystroke(&ks) < 0)
        return 0;
    
    if(ks.ucKeyCode == 0)
        return 0;
    
    switch(ks.ucKeyCode) {
        // System Functions
        case XKEY_ESCAPE: { // Quit to dashboard
            exit(0);
        } break;
        case XKEY_DELETE: { // Reboot xbox
            XReboot();
        } break;
        
        // Digital Buttons
        case XKEY_I: { // DPAD UP
            process_digital_button(&ks, 0x00000001);
        } break;
        case XKEY_K: { // DPAD DOWN
            process_digital_button(&ks, 0x00000002);
        } break;
        case XKEY_J: { // DPAD LEFT
            process_digital_button(&ks, 0x00000004);
        } break;
        case XKEY_L: { // DPAD RIGHT
            process_digital_button(&ks, 0x00000008);
        } break;
        case XKEY_RETURN: { // START
            process_digital_button(&ks, 0x00000010);
        } break;
        case XKEY_BACKSPACE: { // BACK
            process_digital_button(&ks, 0x00000020);
        } break;
        case XKEY_R: { // Left Stick Click
            process_digital_button(&ks, 0x00000040);
        } break;
        case XKEY_T: { // Right Stick Click
            process_digital_button(&ks, 0x00000080);
        } break;
        
        // Analog Buttons
        case XKEY_SPACE: { // A
            process_analog_button(&ks, 0);
        } break;
        case XKEY_C: { // B
            process_analog_button(&ks, 1);
        } break;
        case XKEY_Z: { // X
            process_analog_button(&ks, 2);
        } break;
        case XKEY_X: { // Y
            process_analog_button(&ks, 3);
        } break;
        case XKEY_1: { // Black
            process_analog_button(&ks, 4);
        } break;
        case XKEY_3: { // White
            process_analog_button(&ks, 5);
        } break;
        case XKEY_Q: { // Left Trigger
            process_analog_button(&ks, 6);
        } break;
        case XKEY_E: { // Right Trigger
            process_analog_button(&ks, 7);
        } break;
        
        // Thumbsticks
        case XKEY_UP: { // Left Stick Up
            process_thumbsticks(&ks, &pad.Gamepad.sThumbLY, TRUE);
        } break;
        case XKEY_DOWN: { // Left Stick Down
            process_thumbsticks(&ks, &pad.Gamepad.sThumbLY, FALSE);
        } break;
        case XKEY_LEFT: { // Left Stick Left
            process_thumbsticks(&ks, &pad.Gamepad.sThumbLX, FALSE);
        } break;
        case XKEY_RIGHT: { // Left Stick Right
            process_thumbsticks(&ks, &pad.Gamepad.sThumbLX, TRUE);
        } break;
        
        case XKEY_W: { // Right Stick Up
            process_thumbsticks(&ks, &pad.Gamepad.sThumbRY, TRUE);
        } break;
        case XKEY_S: { // Right Stick Down
            process_thumbsticks(&ks, &pad.Gamepad.sThumbRY, FALSE);
        } break;
        case XKEY_A: { // Right Stick Left
            process_thumbsticks(&ks, &pad.Gamepad.sThumbRX, FALSE);
        } break;
        case XKEY_D: { // Right Stick Right
            process_thumbsticks(&ks, &pad.Gamepad.sThumbRX, TRUE);
        } break;
    }
    
    memcpy(pState, &pad, sizeof(XINPUT_STATE));
    
    return 0;
}

VOID WINAPI Hook_XInputClose(PVOID hDevice) {
    free(hDevice);
}

VOID CDECL scanned_func(const char* library_str, uint32_t library_flag, const char* symbol_str, uint32_t func_addr, uint32_t revision) {
    if(!strcmp("XInitDevices", symbol_str)) {
        Addr_XInitDevices = func_addr;
        XInitDevices_found = true;
    }
    else if(!strcmp("XGetDevices", symbol_str)) {
        Addr_XGetDevices = func_addr;
        XGetDevices_found = true;
    }
    else if(!strcmp("XGetDeviceChanges", symbol_str)) {
        Addr_XGetDeviceChanges = func_addr;
        XGetDeviceChanges_found = true;
    }
    else if(!strcmp("XInputOpen", symbol_str)) {
        Addr_XInputOpen = func_addr;
        XInputOpen_found = true;
    }
    else if(!strcmp("XInputGetState", symbol_str)) {
        Addr_XInputGetState = func_addr;
        XInputGetState_found = true;
    }
    else if(!strcmp("XInputClose", symbol_str)) {
        Addr_XInputClose = func_addr;
        XInputClose_found = true;
    }
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
	
	if(!XbSymbolDatabase_CreateXbSymbolContext(&xapi_handle, scanned_func, lib_header, sec_header, thunk_addr)) {
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
    if (Notification != DM_MODLOAD) {
        return 0;
    }
    
    // Early out if no XBE was loaded
    if ((XeImageFileName->Length == 0) || (XeImageFileName->Buffer == NULL)) {
        return 0;
    }
    
    // First, scan for XInput function locations
    ScanForSymbols();
    
    uint32_t cert_addr = *(DWORD*)0x00010118;
    
    // Hook XInput functions
    hook_function(Hook_XInitDevices, Addr_XInitDevices, XInitDevices_found);
    hook_function(Hook_XGetDevices, Addr_XGetDevices, XGetDevices_found);
    //hook_function(Hook_XGetDeviceChanges, Addr_XGetDeviceChanges, XGetDeviceChanges_found);
    hook_function(Hook_XInputOpen, Addr_XInputOpen, XInputOpen_found);
    hook_function(Hook_XInputGetState, Addr_XInputGetState, XInputGetState_found);
    hook_function(Hook_XInputClose, Addr_XInputClose, XInputClose_found);
    
    memset(&pad, 0, sizeof(XINPUT_STATE));
    
    return 0;
}

int main() { (void)KeTickCount; return 0; }

void DxtEntry(ULONG *pfUnload) {
    static PDMN_SESSION DmSession;
    
    HRESULT hr = DmOpenNotificationSession(DM_PERSISTENT, &DmSession);
    
    if (SUCCEEDED(hr)) {
        hr = DmNotify(DmSession, DM_MODLOAD, modload_callback);
    }
    
    if (SUCCEEDED(hr)) {
        *pfUnload = FALSE;
    } else {
        *pfUnload = TRUE;
    }
}
