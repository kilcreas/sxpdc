#ifndef GDBUS_INTERFACE_H_
#define GDBUS_INTERFACE_H_

struct sxpd_gdbus_ctx;

/**
 * @brief gdbus context create and gdbus interface initialization.
 *
 * @param[out] ctx gdbus context
 * @param sxpd_ctx sxpd context
 * @param evmgr event manager
 *
 * @return 0 on success, -1 on error
 */
int sxpd_gdbus_interface_init(struct sxpd_gdbus_ctx **ctx,
                              struct sxpd_ctx *sxpd_ctx, struct evmgr *evmgr);

/**
 * @brief gdbus interface deinitialization, gdbus context destroy.
 *
 * @param ctx gdbsu context
 * @return
 */
int sxpd_gdbus_interface_deinit(struct sxpd_gdbus_ctx *ctx);

#endif /* GDBUS_INTERFACE_H_ */
