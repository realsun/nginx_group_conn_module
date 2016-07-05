 
 
/**
 * @file ngx_http_group_conn_module.c
 * @date 2016/06/29 17:44:46
 * @brief 模块可以按照指定的维度进行connection的统计，并定义变量，其他阶段可以根据维度的名称（如host）获得当前相应的connections数量
 *  
 **/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

// 共享内存的红黑树节点
typedef struct {
    u_char      color;   // 对齐ngx_rbtree_node_s结构体中的color
    u_short     len;     // 红黑树中key的长度
    ngx_uint_t  count;   // 连接数
    u_char      data[1]; // 红黑树中key的文本
} ngx_http_group_conn_node_t;

// location级别配置信息
typedef struct {
    ngx_shm_zone_t *shm_zone;
    ngx_flag_t      enable;
    ngx_int_t       group_name_index;
} ngx_http_group_conn_loc_conf_t;

// 共享内存的data，reload阶段有继承作用
typedef struct {
    ngx_rbtree_t       *rbtree;
    ngx_slab_pool_t    *shpool;
} ngx_http_group_conn_shmctx_t;

// 析构时需要关联的指针
typedef struct {
    ngx_shm_zone_t     *shm_zone;
    ngx_rbtree_node_t  *node;
} ngx_http_group_conn_cleanup_t;

static char *ngx_http_group_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_group_conn_switch(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_group_conn_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_http_group_conn_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_group_conn_merge_loc_conf(ngx_conf_t *cf, void *parent, 
    void *child);
static ngx_int_t ngx_http_group_conn_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static void ngx_http_group_conn_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_int_t ngx_http_group_conn_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_group_conn_handler(ngx_http_request_t *r);
static void ngx_http_group_conn_cleanup(void *data);
static ngx_rbtree_node_t *ngx_http_group_conn_rbtree_lookup(ngx_rbtree_t *rbtree,
    ngx_http_variable_value_t *vv, uint32_t hash);
static ngx_int_t ngx_http_group_conn_get_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_group_conn_add_variables(ngx_conf_t *cf);

// 解析每个模块配置参数，在create之后，在merge之前
static ngx_command_t ngx_http_group_conn_commands[] = {
    { ngx_string("group_conn_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_group_conn_zone,
      0,
      0,
      NULL },

    { ngx_string("group_conn_switch"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_group_conn_switch,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("group_conn_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_group_conn_key,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

// 定义http module
static ngx_http_module_t ngx_http_group_conn_module_ctx = {
    ngx_http_group_conn_add_variables,     /* preconfiguration */
    ngx_http_group_conn_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_group_conn_create_loc_conf,   /* create location configuration */
    ngx_http_group_conn_merge_loc_conf     /* merge location configuration */
};

// 定义module
ngx_module_t ngx_http_group_conn_module = {
    NGX_MODULE_V1,
    &ngx_http_group_conn_module_ctx,   /* module context */
    ngx_http_group_conn_commands,      /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};

// 模块共享内存的名字
static ngx_str_t ngx_http_group_conn_zone_name = ngx_string("group_conn_zone_name");

// 定义内部变量，其他模块可以访问到，如log
// 结构:{name, set_handler, get_handler, data, flags, index} 
static ngx_http_variable_t ngx_http_group_conn_vars[] = {
    { ngx_string("group_connections"), NULL, 
      ngx_http_group_conn_get_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static char *ngx_http_group_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf) {
    ssize_t   size;
    ngx_uint_t   i;
    ngx_str_t    s;
    ngx_str_t *value;
    ngx_shm_zone_t  *shm_zone;
    ngx_http_group_conn_shmctx_t *shmctx;

    value = cf->args->elts;

    shmctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_group_conn_shmctx_t));
    if (shmctx == NULL) {
        return NGX_CONF_ERROR;
    }

    size = 0;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "size=", 5) == 0) {
            s.data = value[i].data + 5;
            s.len = value[i].data + value[i].len - s.data;
            size = ngx_parse_size(&s);

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    } // end for

    shm_zone = ngx_shared_memory_add(cf, &ngx_http_group_conn_zone_name, size,
                                     &ngx_http_group_conn_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound", &cmd->name, &ngx_http_group_conn_zone_name);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_group_conn_init_zone;
    shm_zone->data = shmctx;

    return NGX_CONF_OK;
}


static char *ngx_http_group_conn_switch(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf) {
    ngx_http_group_conn_loc_conf_t *gclcf = conf;

    ngx_str_t                      *value;
    ngx_shm_zone_t                 *shm_zone;

    value = cf->args->elts;

    if (gclcf->enable != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    if (ngx_strcasecmp(value[1].data, (u_char *) "on") == 0) {
        gclcf->enable = 1;

    } else if (ngx_strcasecmp(value[1].data, (u_char *) "off") == 0) {
        gclcf->enable = 0;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "invalid value \"%s\" in \"%s\" directive, "
                     "it must be \"on\" or \"off\"",
                     value[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &ngx_http_group_conn_zone_name, 0,
                                     &ngx_http_group_conn_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    gclcf->shm_zone = shm_zone;

    return NGX_CONF_OK;
}

static char *ngx_http_group_conn_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf) {
    ngx_http_group_conn_loc_conf_t *gclcf = conf;

    ngx_str_t                      *value;
    ngx_shm_zone_t                 *shm_zone;

    value = cf->args->elts;

    if (value[1].data[0] == '$') {
        value[1].len--;
        value[1].data++;
        gclcf->group_name_index = ngx_http_get_variable_index(cf, &value[1]);
        
        if (gclcf->group_name_index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "group module invalid key \"%s\"", value[1].data);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &ngx_http_group_conn_zone_name, 0,
                                     &ngx_http_group_conn_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    gclcf->shm_zone = shm_zone;

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_group_conn_init_zone(ngx_shm_zone_t *shm_zone, void *data) {
    ngx_http_group_conn_shmctx_t *oshmctx = data;

    size_t                        len;
    ngx_slab_pool_t              *shpool;
    ngx_rbtree_node_t            *sentinel;
    ngx_http_group_conn_shmctx_t *shmctx;

    shmctx = shm_zone->data;

    if (oshmctx) {
        shmctx->rbtree = oshmctx->rbtree;
        shmctx->shpool = oshmctx->shpool;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    shmctx->shpool = shpool;

    if (shm_zone->shm.exists) {
        shmctx->rbtree = shpool->data;
        return NGX_OK;
    }

    // 首次为红黑树申请空间
    shmctx->rbtree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    if (shmctx->rbtree == NULL) {
        return NGX_ERROR;
    }
    shpool->data = shmctx->rbtree;

    // 申请红黑树哨兵节点
    sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(shmctx->rbtree, sentinel,
                    ngx_http_group_conn_rbtree_insert_value);
    
    len = sizeof(" in group_conn_zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in group_conn_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}

static void ngx_http_group_conn_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel) {

    ngx_rbtree_node_t           **p;
    ngx_http_group_conn_node_t   *lcn, *lcnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lcn = (ngx_http_group_conn_node_t *) &node->color; // node内部空间
            lcnt = (ngx_http_group_conn_node_t *) &temp->color;

            p = (ngx_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        // leaf节点都会指向哨兵
        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    // p是插入槽位，temp此时是父节点
    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


// post configuration
// 在preaccess阶段在红黑树中为key的计数加一
static ngx_int_t ngx_http_group_conn_init(ngx_conf_t *cf) {
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_group_conn_handler;

    return NGX_OK;
}

// 将指定key的红黑树中的值加一，并加入cleanup，以便在析构request时，将此值减一
static ngx_int_t ngx_http_group_conn_handler(ngx_http_request_t *r) {
    ngx_http_group_conn_loc_conf_t *gclcf = NULL;
    ngx_http_variable_value_t      *vv = NULL;
    size_t                          n;
    size_t                          len;
    uint32_t                        hash;
    ngx_slab_pool_t                *shpool = NULL;
    ngx_rbtree_node_t              *node = NULL;
    ngx_http_group_conn_shmctx_t   *shmctx = NULL;
    ngx_http_group_conn_node_t     *gc = NULL;
    ngx_pool_cleanup_t             *cln = NULL;
    ngx_http_group_conn_cleanup_t  *gccln = NULL;

    gclcf = ngx_http_get_module_loc_conf(r, ngx_http_group_conn_module);
    
    if (gclcf->enable != 1) {
        return NGX_DECLINED;
    }

    // 1、获取key
    vv = ngx_http_get_indexed_variable(r, gclcf->group_name_index);

    if (vv == NULL || vv->not_found) {
        return NGX_DECLINED;
    }

    len = vv->len;

    if (len == 0) {
        return NGX_DECLINED;
    }

    // 限制key的长度，红黑树中是用ushort存，所以最大不能大于65535
    if (len > 1024) {
        return NGX_DECLINED;
    }

    // 2、在红黑树中计数加一
    // shpool指向的data也是rbtree
    hash = ngx_crc32_short(vv->data, len);

    shpool = (ngx_slab_pool_t *)gclcf->shm_zone->shm.addr;

    shmctx = (ngx_http_group_conn_shmctx_t *)gclcf->shm_zone->data;

    ngx_shmtx_lock(&shpool->mutex);

    node = ngx_http_group_conn_rbtree_lookup(shmctx->rbtree, vv, hash);

    // 树中无此key
    if (node == NULL) {
        // node size: size(ngx_rbtree_node_t[key ~ parent]) 
        // + size(ngx_http_group_conn_node_t[color ~ count])
        // + size(key)
        // 不要访问ngx_rbtree_node_t.data，这个值被冲掉了
        n = offsetof(ngx_rbtree_node_t, color)
            + offsetof(ngx_http_group_conn_node_t, data)
            + len;

        node = ngx_slab_alloc_locked(shpool, n);
        
        if (node == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        gc = (ngx_http_group_conn_node_t *) &node->color;

        node->key = hash;
        gc->len = (u_short)len;
        gc->count = 1;
        ngx_memcpy(gc->data, vv->data, len);

        ngx_rbtree_insert(shmctx->rbtree, node);
    } else {
        gc = (ngx_http_group_conn_node_t *) &node->color;

        gc->count++;
    }

    ngx_shmtx_unlock(&shpool->mutex);
    
    // 3、cleanup阶段计数减一
    cln = ngx_pool_cleanup_add(r->pool,
            sizeof(ngx_http_group_conn_cleanup_t));

    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln->handler = ngx_http_group_conn_cleanup;
    gccln = cln->data;

    // 传入共享内存地址和本次操作的node
    gccln->shm_zone = gclcf->shm_zone;
    gccln->node = node;

    return NGX_DECLINED;
}

static void *ngx_http_group_conn_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_group_conn_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_group_conn_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->group_name_index = NGX_CONF_UNSET;

    return conf;
}

static char *ngx_http_group_conn_merge_loc_conf(ngx_conf_t *cf, void *parent, 
    void *child) {
    ngx_http_group_conn_loc_conf_t *prev = parent;
    ngx_http_group_conn_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->group_name_index, prev->group_name_index, -1);

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    return NGX_CONF_OK;
}

static void ngx_http_group_conn_cleanup(void *data) {
    ngx_http_group_conn_cleanup_t *gccln = data;

    ngx_slab_pool_t               *shpool = NULL;
    ngx_rbtree_node_t             *node = NULL;
    ngx_http_group_conn_shmctx_t  *shmctx = NULL;
    ngx_http_group_conn_node_t    *gc = NULL;

    shmctx = (ngx_http_group_conn_shmctx_t *)gccln->shm_zone->data;
    shpool = (ngx_slab_pool_t *)gccln->shm_zone->shm.addr;
    node = gccln->node;
    gc = (ngx_http_group_conn_node_t *) &node->color;

    ngx_shmtx_lock(&shpool->mutex);

    gc->count--;

    if (gc->count == 0) {
        ngx_rbtree_delete(shmctx->rbtree, node);
        ngx_slab_free_locked(shpool, node);
    }

    ngx_shmtx_unlock(&shpool->mutex);
}

static ngx_rbtree_node_t *ngx_http_group_conn_rbtree_lookup(ngx_rbtree_t *rbtree,
        ngx_http_variable_value_t *vv, uint32_t hash) {
   
    ngx_int_t                    rc;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_http_group_conn_node_t  *lcn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        lcn = (ngx_http_group_conn_node_t *) &node->color;

        rc = ngx_memn2cmp(vv->data, lcn->data,
                          (size_t) vv->len, (size_t) lcn->len);
        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

// 获取变量的回调，判断开关，查询红黑树
static ngx_int_t ngx_http_group_conn_get_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {

    ngx_http_group_conn_loc_conf_t *gclcf = NULL;
    ngx_http_variable_value_t      *vv = NULL;
    size_t                          len;
    uint32_t                        hash;
    ngx_uint_t                      conn_count;
    ngx_slab_pool_t                *shpool = NULL;
    ngx_rbtree_node_t              *node = NULL;
    ngx_http_group_conn_shmctx_t   *shmctx = NULL;
    ngx_http_group_conn_node_t     *gc = NULL;

    gclcf = ngx_http_get_module_loc_conf(r, ngx_http_group_conn_module);
    
    if (gclcf->enable != 1) {
        goto not_found;
    }

    vv = ngx_http_get_indexed_variable(r, gclcf->group_name_index);

    if (vv == NULL || vv->not_found) {
        goto not_found;
    }

    len = vv->len;

    if (len == 0 || len > 1024) {
        goto not_found;
    }

    hash = ngx_crc32_short(vv->data, len);

    shpool = (ngx_slab_pool_t *)gclcf->shm_zone->shm.addr;

    shmctx = (ngx_http_group_conn_shmctx_t *)gclcf->shm_zone->data;

    ngx_shmtx_lock(&shpool->mutex);

    node = ngx_http_group_conn_rbtree_lookup(shmctx->rbtree, vv, hash);

    if (node == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        goto not_found;
    } else {
        gc = (ngx_http_group_conn_node_t *) &node->color;
        conn_count = gc->count;

        u_char *p = NULL;
        p = ngx_pnalloc(r->pool, NGX_INT32_LEN);
        if (p == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            goto not_found;
        }

        v->len = ngx_sprintf(p, "%ui", conn_count) - p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = p;
    }

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;

not_found:
    v->not_found = 1;
    return NGX_OK;

}


static ngx_int_t ngx_http_group_conn_add_variables(ngx_conf_t *cf) {

   ngx_http_variable_t  *var, *v;

    for (v = ngx_http_group_conn_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


/* vim: set expandtab ts=4 sw=4 sts=4 tw=100: */
