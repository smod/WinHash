#include <windows.h>
#include <wincrypt.h>
#include <tchar.h>
#include <commctrl.h>

#define SZ_HASH 32

enum {
    ID_ES_PATH,
    ID_BN_PATH,
    ID_ES_HASH,
    ID_BN_HASH,
    ID_ES_COMPARE,
    ID_BN_COMPARE
};

static LRESULT CALLBACK BnPathBnClicked(HWND hWnd) {
    OPENFILENAME ofn;
    TCHAR lpstrFile[MAX_PATH];

    ZeroMemory(&ofn, sizeof ofn);
    ZeroMemory(lpstrFile, sizeof lpstrFile);

    ofn.lStructSize = sizeof ofn;
    ofn.hwndOwner = hWnd;
    ofn.lpstrFile = lpstrFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

    if (GetOpenFileName(&ofn)) {
        SetDlgItemText(hWnd, ID_ES_PATH, ofn.lpstrFile);
    }

    return 0;
}

static LRESULT CALLBACK BnHashBnClicked(HWND hWnd) {
    TCHAR lpstrFile[MAX_PATH];
    HANDLE hFile;

    GetDlgItemText(hWnd, ID_ES_PATH, lpstrFile, sizeof lpstrFile);

    hFile = CreateFile(lpstrFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        HCRYPTPROV hCryptProv;
        HCRYPTHASH hCryptHash;
        BYTE bData[1024];
        DWORD dwDataLen;
        TCHAR lpstrHash[SZ_HASH + 1];
        DWORD dwDataIndex;

        CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
        CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hCryptHash);

        while (ReadFile(hFile, bData, sizeof bData, &dwDataLen, NULL) && dwDataLen > 0) {
            CryptHashData(hCryptHash, bData, dwDataLen, 0);
        }

        dwDataLen = 16;
        CryptGetHashParam(hCryptHash, HP_HASHVAL, bData, &dwDataLen, 0);

        for (dwDataIndex = 0; dwDataIndex < dwDataLen; ++dwDataIndex) {
            wsprintf(lpstrHash + dwDataIndex * 2, TEXT("%02x"), bData[dwDataIndex]);
        }

        SetDlgItemText(hWnd, ID_ES_HASH, lpstrHash);

        CryptDestroyHash(hCryptHash);
        CryptReleaseContext(hCryptProv, 0);
        CloseHandle(hFile);
    } else {
        MessageBox(hWnd, TEXT("Please select a readable file before."), TEXT(""), MB_OK);
    }

    return 0;
}

static LRESULT CALLBACK BnCompareBnClicked(HWND hWnd) {
    TCHAR lpstrHash[SZ_HASH];
    TCHAR lpstrCompare[SZ_HASH];

    GetDlgItemText(hWnd, ID_ES_HASH, lpstrHash, sizeof lpstrHash);
    GetDlgItemText(hWnd, ID_ES_COMPARE, lpstrCompare, sizeof lpstrCompare);

    if (_tcsicmp(lpstrHash, lpstrCompare) == 0) {
        MessageBox(hWnd, TEXT("Hash matches."), TEXT(""), MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBox(hWnd, TEXT("Hash does not match."), TEXT(""), MB_OK | MB_ICONINFORMATION);
    }

    return 0;
}

static LRESULT CALLBACK WndMainProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
        CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), NULL, WS_CHILD | WS_VISIBLE | ES_READONLY | ES_AUTOHSCROLL, 20, 22, 260, 24, hWnd, (HMENU) ID_ES_PATH, NULL, NULL);
        CreateWindowEx(0, TEXT("BUTTON"), TEXT("Browse"), WS_CHILD | WS_VISIBLE, 300, 20, 80, 30, hWnd, (HMENU) ID_BN_PATH, NULL, NULL);
        CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), NULL, WS_CHILD | WS_VISIBLE | ES_READONLY | ES_AUTOHSCROLL, 20, 62, 260, 24, hWnd, (HMENU) ID_ES_HASH, NULL, NULL);
        CreateWindowEx(0, TEXT("BUTTON"), TEXT("Hash"), WS_CHILD | WS_VISIBLE, 300, 60, 80, 30, hWnd, (HMENU) ID_BN_HASH, NULL, NULL);
        CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), NULL, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 20, 102, 260, 24, hWnd, (HMENU) ID_ES_COMPARE, NULL, NULL);
        SendMessage(GetDlgItem(hWnd, ID_ES_COMPARE), EM_LIMITTEXT, (WPARAM) SZ_HASH, (LPARAM) 0);
        CreateWindowEx(0, TEXT("BUTTON"), TEXT("Compare"), WS_CHILD | WS_VISIBLE, 300, 100, 80, 30, hWnd, (HMENU) ID_BN_COMPARE, NULL, NULL);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    case WM_COMMAND:
    switch (LOWORD(wParam)) {
        case ID_BN_PATH:
            switch (HIWORD(wParam)) {
            case BN_CLICKED:
                return BnPathBnClicked(hWnd);
            }

        case ID_BN_HASH:
            switch (HIWORD(wParam)) {
            case BN_CLICKED:
                return BnHashBnClicked(hWnd);
            }

        case ID_BN_COMPARE:
            switch (HIWORD(wParam)) {
            case BN_CLICKED:
                return BnCompareBnClicked(hWnd);
            }
        }
    }

    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpszArgument, int nCmdShow) {
    WNDCLASS wc;
    HWND hWnd;
    MSG uMsg;

    ZeroMemory(&wc, sizeof wc);

    wc.lpfnWndProc = WndMainProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH) (COLOR_WINDOW);
    wc.lpszClassName = TEXT("WndMain");

    RegisterClass(&wc);
    InitCommonControls();

    hWnd = CreateWindowEx(0, TEXT("WndMain"), TEXT("WinHash"), WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 400, 180, NULL, NULL, hInstance, NULL);

    ShowWindow(hWnd, nCmdShow);

    while (GetMessage(&uMsg, NULL, 0, 0) > 0) {
        TranslateMessage(&uMsg);
        DispatchMessage(&uMsg);
    }

    (void) hPrevInstance;
    (void) lpszArgument;

    return uMsg.wParam;
}
