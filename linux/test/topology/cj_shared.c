#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include <sys/wait.h>

#include <inttypes.h>
#include <sxpd.h>
#include <config.h>
#include <debug.h>
#include <radix.h>
#include <util.h>

#include <mem.h>
#include <config.h>
#include <util.h>

#include "../framework/inc/log_check.h"
#include "../framework/inc/topology.h"

struct topo_task_wait_for_sync_ctx {
    const char *file_path;
    bool file_created;
};

#define TOPO_TASK_WAIT_FOR_SYNC(file_path_)             \
    {                                                   \
        .file_path = file_path_, .file_created = false, \
    }

int topo_task_wait_for_sync_cb(struct topo_task *topo_task)
{
    int rc = 0;
    struct topo_task_wait_for_sync_ctx *sync_ctx = NULL;
    FILE *f = NULL;

    PARAM_NULL_CHECK(rc, topo_task);
    RC_CHECK(rc, out);

    sync_ctx =
        (struct topo_task_wait_for_sync_ctx *)topo_task->task.wait.wait_cb_ctx;

    PARAM_NULL_CHECK(rc, sync_ctx, sync_ctx->file_path);
    RC_CHECK(rc, out);

    if (false == sync_ctx->file_created) {
        topo_task->task.wait.wait_status = TOPO_TASK_WAIT;
        f = fopen(sync_ctx->file_path, "w");
        if (NULL == f) {
            TOPO_TASK_ERROR(topo_task, "failed to open sync file %s for write",
                            sync_ctx->file_path);
            rc = -1;
            goto out;
        }
        fclose(f);
        sync_ctx->file_created = true;
    } else {
        f = fopen(sync_ctx->file_path, "r");
        if (NULL == f) {
            sync_ctx->file_created = false;
            topo_task->task.wait.wait_status = TOPO_TASK_WAIT_DONE;
        }
    }

out:
    return rc;
}
