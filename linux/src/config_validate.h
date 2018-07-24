/*------------------------------------------------------------------
 * Configuration validation API
 *
 * February 2015, Jan Omasta
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#ifndef CONFIG_VALIDATE_H_
#define CONFIG_VALIDATE_H_

#include <stdint.h>
#include <stdlib.h>

/**
 * @brief validate configuration file
 *
 * @param file_path configuration file path
 * @param error preallocated buffer for error string
 * @param error_size preallocated error string size
 * @return 0 on configuration validation success, 1 on configuration validation
 *           syntax error, -1 on internal error
 */
int cfg_validate(const char *file_path, char *error, size_t error_size);

#endif /* CONFIG_VALIDATE_H_ */
