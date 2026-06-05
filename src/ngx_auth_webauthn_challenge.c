/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_auth_webauthn_challenge.h"

#include <openssl/rand.h>


/*
 * One stored challenge.  node.key is the rbtree key (first four challenge
 * bytes); queue threads every node in insertion (== expiry) order so issue()
 * can trim from the front.  challenge holds the full nonce for exact match.
 */
typedef struct {
    ngx_rbtree_node_t  node;
    ngx_queue_t        queue;
    time_t             expires;
    u_char             challenge[NGX_AUTH_WEBAUTHN_CHALLENGE_LEN];
} ngx_auth_webauthn_challenge_node_t;


struct ngx_auth_webauthn_challenge_sh_s {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_queue_t        queue;
};


/*
 * Derive the rbtree key from the first four challenge bytes.  Collisions are
 * fine: the insert / lookup helpers fall back to a full 32-byte compare.
 */
static ngx_rbtree_key_t
ngx_auth_webauthn_challenge_key(const u_char *c)
{
    return ((ngx_rbtree_key_t) c[0] << 24) | ((ngx_rbtree_key_t) c[1] << 16)
           | ((ngx_rbtree_key_t) c[2] << 8) | (ngx_rbtree_key_t) c[3];
}


/*
 * rbtree insert ordered by (node.key, then memcmp of the full challenge).
 * The same ordering drives the lookup descent so equal-key nodes stay
 * reachable.
 */
static void
ngx_auth_webauthn_challenge_rbtree_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t **p;
    ngx_auth_webauthn_challenge_node_t *cn, *cnt;

    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else {
            cn = (ngx_auth_webauthn_challenge_node_t *) node;
            cnt = (ngx_auth_webauthn_challenge_node_t *) temp;

            p = (ngx_memcmp(cn->challenge, cnt->challenge,
                            NGX_AUTH_WEBAUTHN_CHALLENGE_LEN) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }
        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


/* Find the node holding exactly challenge[0..32); NULL if absent. */
static ngx_auth_webauthn_challenge_node_t *
ngx_auth_webauthn_challenge_lookup(ngx_auth_webauthn_challenge_sh_t *sh,
    const u_char *challenge)
{
    ngx_rbtree_key_t key;
    ngx_rbtree_node_t *node, *sentinel;
    ngx_auth_webauthn_challenge_node_t *cn;
    ngx_int_t rc;

    key = ngx_auth_webauthn_challenge_key(challenge);
    node = sh->rbtree.root;
    sentinel = sh->rbtree.sentinel;

    while (node != sentinel) {
        if (key < node->key) {
            node = node->left;
            continue;
        }
        if (key > node->key) {
            node = node->right;
            continue;
        }

        /* key matches: disambiguate by the full challenge. */
        cn = (ngx_auth_webauthn_challenge_node_t *) node;
        rc = ngx_memcmp(challenge, cn->challenge,
                        NGX_AUTH_WEBAUTHN_CHALLENGE_LEN);
        if (rc == 0) {
            return cn;
        }
        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void
ngx_auth_webauthn_challenge_remove(ngx_auth_webauthn_challenge_sh_t *sh,
    ngx_slab_pool_t *shpool, ngx_auth_webauthn_challenge_node_t *cn)
{
    ngx_queue_remove(&cn->queue);
    ngx_rbtree_delete(&sh->rbtree, &cn->node);
    ngx_slab_free_locked(shpool, cn);
}


/* Drop expired entries from the front of the queue (oldest first). */
static void
ngx_auth_webauthn_challenge_expire(ngx_auth_webauthn_challenge_sh_t *sh,
    ngx_slab_pool_t *shpool, time_t now)
{
    ngx_queue_t *q;
    ngx_auth_webauthn_challenge_node_t *cn;

    while (!ngx_queue_empty(&sh->queue)) {
        q = ngx_queue_head(&sh->queue);
        cn = ngx_queue_data(q, ngx_auth_webauthn_challenge_node_t, queue);

        if (cn->expires > now) {
            break;      /* queue is in expiry order; nothing older remains */
        }
        ngx_auth_webauthn_challenge_remove(sh, shpool, cn);
    }
}


ngx_int_t
ngx_auth_webauthn_challenge_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_auth_webauthn_challenge_ctx_t *octx = data;
    ngx_auth_webauthn_challenge_ctx_t *ctx;
    ngx_slab_pool_t *shpool;

    ctx = shm_zone->data;

    /* Reload: inherit the live state from the previous incarnation. */
    if (octx != NULL) {
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    /* Existing segment (e.g. binary upgrade): reuse what is there. */
    if (shm_zone->shm.exists) {
        ctx->sh = shpool->data;
        ctx->shpool = shpool;
        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(shpool, sizeof(ngx_auth_webauthn_challenge_sh_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }
    ctx->shpool = shpool;
    shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_auth_webauthn_challenge_rbtree_insert);
    ngx_queue_init(&ctx->sh->queue);

    shpool->log_ctx = ngx_slab_alloc(shpool, ngx_strlen(" in challenge zone "
                                                        "\"\"") +
                                     shm_zone->shm.name.len);
    if (shpool->log_ctx != NULL) {
        ngx_sprintf(shpool->log_ctx, " in challenge zone \"%V\"%Z",
                    &shm_zone->shm.name);
    }

    return NGX_OK;
}


ngx_int_t
ngx_auth_webauthn_challenge_issue(ngx_shm_zone_t *shm_zone, u_char *out,
    time_t ttl)
{
    ngx_auth_webauthn_challenge_ctx_t *ctx;
    ngx_auth_webauthn_challenge_sh_t *sh;
    ngx_slab_pool_t *shpool;
    ngx_auth_webauthn_challenge_node_t *cn;
    u_char challenge[NGX_AUTH_WEBAUTHN_CHALLENGE_LEN];
    time_t now;

    if (shm_zone == NULL || out == NULL) {
        return NGX_ERROR;
    }

    if (RAND_bytes(challenge, NGX_AUTH_WEBAUTHN_CHALLENGE_LEN) != 1) {
        return NGX_ERROR;
    }

    ctx = shm_zone->data;
    sh = ctx->sh;
    shpool = ctx->shpool;
    now = ngx_time();

    ngx_shmtx_lock(&shpool->mutex);

    ngx_auth_webauthn_challenge_expire(sh, shpool, now);

    cn = ngx_slab_alloc_locked(shpool,
                               sizeof(ngx_auth_webauthn_challenge_node_t));
    if (cn == NULL) {
        /* Slab full: evict the oldest entry and retry once. */
        if (!ngx_queue_empty(&sh->queue)) {
            ngx_queue_t *q = ngx_queue_head(&sh->queue);
            ngx_auth_webauthn_challenge_remove(sh, shpool,
                                               ngx_queue_data(q,
                                                              ngx_auth_webauthn_challenge_node_t,
                                                              queue));
            cn = ngx_slab_alloc_locked(shpool,
                                       sizeof(ngx_auth_webauthn_challenge_node_t));
        }
        if (cn == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            ngx_log_error(NGX_LOG_ERR, shm_zone->shm.log, 0,
                          "auth_webauthn: challenge zone \"%V\" is full",
                          &shm_zone->shm.name);
            return NGX_ERROR;
        }
    }

    cn->node.key = ngx_auth_webauthn_challenge_key(challenge);
    cn->expires = now + ttl;
    ngx_memcpy(cn->challenge, challenge, NGX_AUTH_WEBAUTHN_CHALLENGE_LEN);

    ngx_rbtree_insert(&sh->rbtree, &cn->node);
    ngx_queue_insert_tail(&sh->queue, &cn->queue);

    ngx_shmtx_unlock(&shpool->mutex);

    ngx_memcpy(out, challenge, NGX_AUTH_WEBAUTHN_CHALLENGE_LEN);

    return NGX_OK;
}


ngx_int_t
ngx_auth_webauthn_challenge_consume(ngx_shm_zone_t *shm_zone,
    const u_char *challenge, size_t len)
{
    ngx_auth_webauthn_challenge_ctx_t *ctx;
    ngx_auth_webauthn_challenge_sh_t *sh;
    ngx_slab_pool_t *shpool;
    ngx_auth_webauthn_challenge_node_t *cn;
    ngx_int_t rc;
    time_t now;

    if (shm_zone == NULL || challenge == NULL) {
        return NGX_ERROR;
    }
    if (len != NGX_AUTH_WEBAUTHN_CHALLENGE_LEN) {
        return NGX_DECLINED;
    }

    ctx = shm_zone->data;
    sh = ctx->sh;
    shpool = ctx->shpool;
    now = ngx_time();

    ngx_shmtx_lock(&shpool->mutex);

    cn = ngx_auth_webauthn_challenge_lookup(sh, challenge);
    if (cn == NULL) {
        rc = NGX_DECLINED;

    } else if (cn->expires <= now) {
        /* Stale: remove it in passing and reject. */
        ngx_auth_webauthn_challenge_remove(sh, shpool, cn);
        rc = NGX_DECLINED;

    } else {
        /* One-shot: a valid challenge is deleted on use. */
        ngx_auth_webauthn_challenge_remove(sh, shpool, cn);
        rc = NGX_OK;
    }

    ngx_shmtx_unlock(&shpool->mutex);

    return rc;
}
