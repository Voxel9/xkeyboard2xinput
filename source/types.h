#ifndef __TYPES_H__
#define __TYPES_H__

// Xbox XInput structs, taken from Cxbx-Reloaded
// (https://github.com/Cxbx-Reloaded/Cxbx-Reloaded/blob/master/src/core/hle/XAPI/Xapi.h)

typedef struct _XINPUT_GAMEPAD {
    WORD    wButtons;
    BYTE    bAnalogButtons[8];
    SHORT   sThumbLX;
    SHORT   sThumbLY;
    SHORT   sThumbRX;
    SHORT   sThumbRY;
} XINPUT_GAMEPAD, *PXINPUT_GAMEPAD;

typedef struct _XINPUT_STATE {
    DWORD dwPacketNumber;
    
    union {
        XINPUT_GAMEPAD Gamepad;
    };
} XINPUT_STATE, *PXINPUT_STATE;

typedef struct _XINPUT_POLLING_PARAMETERS {
    BYTE       fAutoPoll        : 1;
    BYTE       fInterruptOut    : 1;
    BYTE       ReservedMBZ1     : 6;
    BYTE       bInputInterval;
    BYTE       bOutputInterval;
    BYTE       ReservedMBZ2;
} XINPUT_POLLING_PARAMETERS;

typedef struct _POLLING_PARAMETERS_HANDLE {
    XINPUT_POLLING_PARAMETERS *pPollingParameters;

    DWORD dwPort;
} POLLING_PARAMETERS_HANDLE;

#endif
