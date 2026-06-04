/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_config.h - shadows the real nginx header and redirects to ngx_compat.h
 * so the shared sources can be built without an nginx runtime.
 */

#ifndef NGX_CONFIG_H_COMPAT
#define NGX_CONFIG_H_COMPAT

#include "ngx_compat.h"

#endif /* NGX_CONFIG_H_COMPAT */
