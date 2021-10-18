/* SPDX-License-Identifier: BSD-3-Clause */

#include <unistd.h>
#include <getopt.h>
#include <libgen.h>

#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubox/ulog.h>
#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include <libubus.h>
#include <uci.h>
#include <uci_blob.h>

static struct ubus_auto_conn conn;
static int verbose = 1;

static struct publisher {
	char *path;
	char *type;
	char *name;
	int wildcard;
	int raw;
	bool enable;
	char **filter;
} publisher[] = {
	{
		.path = "hostapd.wlan",
		.type = "wifi",
		.name = "wifi-frames",
		.wildcard = 1,
	},
	{
		.path = "dhcpsnoop",
		.type = "dhcp",
		.name = "dhcp-snooping",
		.raw = 1,
	},
};

struct subscriber {
	struct avl_node avl;
	uint32_t id;
	struct publisher *publisher;
	struct ubus_subscriber subscriber;
};

static struct avl_tree subscribers;
static struct blob_buf b;
static uint32_t ucentral;

static struct publisher *
publisher_find(char *type)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(publisher); i++)
		if (!strcmp(publisher[i].type, type))
			return &publisher[i];

	return NULL;
}

static int
avl_intcmp(const void *k1, const void *k2, void *ptr)
{
	return *((uint32_t *)k1) != *((uint32_t *)k2);
}

static struct publisher*
publisher_match(const char *path)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(publisher); i++) {
		int len = strlen(publisher[i].path);

		if (publisher[i].wildcard && strncmp(path, publisher[i].path, len))
			continue;
		if (!publisher[i].wildcard && strcmp(path, publisher[i].path))
			continue;
		return &publisher[i];
	}
	return NULL;
}

static int
publisher_filter(struct publisher *pub, const char *method)
{
	char **filter = pub->filter;

	if (!*filter)
		return 0;

	if (!strcmp(*filter, "*"))
		return 0;

	while (*filter)
		if (!strcmp(*filter++, method))
			return 0;

	return -1;
}

static int
subscriber_notify_cb(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct ubus_subscriber *subscriber = container_of(obj, struct ubus_subscriber, obj);
	struct subscriber *sub = container_of(subscriber, struct subscriber, subscriber);
	struct blob_attr *a;
	void *c, *d;
	int rem;

	if (!sub)
		return 0;

	if (publisher_filter(sub->publisher, method))
		return 0;

	if (verbose) {
		char *str = blobmsg_format_json(msg, true);

		printf("Received ubus notify '%s/%s' : %s\n", sub->publisher->type, method, str);
		free(str);
	}

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "event", sub->publisher->name);
	c = blobmsg_open_table(&b, "payload");
	if (!sub->publisher->raw)
		d = blobmsg_open_table(&b, method);
	blobmsg_for_each_attr(a, msg, rem)
		blobmsg_add_blob(&b, a);
	if (!sub->publisher->raw)
		blobmsg_close_table(&b, d);
	blobmsg_close_table(&b, c);

	ubus_invoke(&conn.ctx, ucentral, "event", b.head, NULL, 0, 1000);

	return 0;
}

static void
subscriber_del(uint32_t id)
{
	struct subscriber *p = avl_find_element(&subscribers, &id, p, avl);

	if (p)
		avl_delete(&subscribers, &p->avl);
}

static void
subscriber_add(struct ubus_context *ctx, char *path, uint32_t id)
{
	struct publisher *publisher = publisher_match(path);
	struct subscriber *sub;

	if (!publisher || !publisher->enable)
		return;
	sub = malloc(sizeof(*sub));

	memset(sub, 0, sizeof(*sub));
	sub->id = id;
	sub->publisher = publisher;
	sub->avl.key = &sub->id;
	sub->subscriber.cb = subscriber_notify_cb;
	if (ubus_register_subscriber(ctx, &sub->subscriber) ||
	    ubus_subscribe(ctx, &sub->subscriber, id)) {
		ULOG_ERR("failed to register ubus publisher\n");
		free(sub);
	} else {
		avl_insert(&subscribers, &sub->avl);
		ULOG_NOTE("Subscribe to %s (%u)\n", path, id);
	}
}

static void
handle_status(struct ubus_context *ctx,  struct ubus_event_handler *ev,
	     const char *type, struct blob_attr *msg)
{
	enum {
		EVENT_ID,
		EVENT_PATH,
		__EVENT_MAX
	};

	static const struct blobmsg_policy status_policy[__EVENT_MAX] = {
		[EVENT_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
		[EVENT_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	};

	struct blob_attr *tb[__EVENT_MAX];
	char *path;
	uint32_t id;

	if (verbose) {
		char *str;

		str = blobmsg_format_json(msg, true);
		printf("Received ubus notify '%s': %s\n", type, str);
		free(str);
	}

	blobmsg_parse(status_policy, __EVENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[EVENT_ID] || !tb[EVENT_PATH])
		return;

	path = blobmsg_get_string(tb[EVENT_PATH]);
	id = blobmsg_get_u32(tb[EVENT_ID]);

	if (!strcmp(path, "ucentral")) {
		if (!strcmp("ubus.object.remove", type))
			ucentral = 0;
		else
			ucentral = id;
		return;
	}

	if (!strcmp("ubus.object.remove", type)) {
		subscriber_del(id);
		return;
	}

	subscriber_add(ctx, path, id);
}

static struct ubus_event_handler status_handler = { .cb = handle_status };

static void
receive_list_result(struct ubus_context *ctx, struct ubus_object_data *obj,
		    void *priv)
{
	char *path = strdup(obj->path);

	subscriber_add(ctx, path, obj->id);
	free(path);
}

static void
ubus_connect_handler(struct ubus_context *ctx)
{
	ULOG_NOTE("connected to ubus\n");

	ubus_register_event_handler(ctx, &status_handler, "ubus.object.add");
	ubus_register_event_handler(ctx, &status_handler, "ubus.object.remove");

	ubus_lookup_id(ctx, "ucentral", &ucentral);
	ubus_lookup(ctx, NULL, receive_list_result, NULL);
}

static void
config_load_publisher(struct uci_section *s)
{
	enum {
		PUBLISHER_ATTR_TYPE,
		PUBLISHER_ATTR_FILTER,
		__PUBLISHER_ATTR_MAX,
	};

	static const struct blobmsg_policy publisher_attrs[__PUBLISHER_ATTR_MAX] = {
		[PUBLISHER_ATTR_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
		[PUBLISHER_ATTR_FILTER] = { .name = "filter", .type = BLOBMSG_TYPE_ARRAY },
	};

	const struct uci_blob_param_list publisher_attr_list = {
		.n_params = __PUBLISHER_ATTR_MAX,
		.params = publisher_attrs,
	};

	struct blob_attr *tb[__PUBLISHER_ATTR_MAX] = { 0 };
	struct publisher *pub;
	struct blob_attr *a;
	int count = 0;
	char **filter;
	int rem;
	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &publisher_attr_list);
	blobmsg_parse(publisher_attrs, __PUBLISHER_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

	if (!tb[PUBLISHER_ATTR_TYPE] || !tb[PUBLISHER_ATTR_FILTER])
		return;

	pub = publisher_find(blobmsg_get_string(tb[PUBLISHER_ATTR_TYPE]));
	if (!pub)
		return;

	ULOG_INFO("enabling %s events\n", pub->type);
	pub->enable = true;

	blobmsg_for_each_attr(a, tb[PUBLISHER_ATTR_FILTER], rem)
		count++;

	count = (count + 1) * sizeof(char *);
	filter = pub->filter = malloc(count);
	memset(filter, 0, count);
	blobmsg_for_each_attr(a, tb[PUBLISHER_ATTR_FILTER], rem)
		if (blobmsg_type(a) == BLOBMSG_TYPE_STRING) {
			*filter = strdup(blobmsg_get_string(a));
			filter++;
		}
}

static void
config_load(void)
{
	struct uci_context *uci = uci_alloc_context();
	struct uci_package *package = NULL;

	if (!uci_load(uci, "event", &package)) {
		struct uci_element *e;

		uci_foreach_element(&package->sections, e) {
			struct uci_section *s = uci_to_section(e);

			if (!strcmp(s->type, "event"))
				config_load_publisher(s);
		}
	}

	uci_unload(uci, package);
	uci_free_context(uci);
}

int
main(int argc, char **argv)
{
	ulog_open(ULOG_STDIO | ULOG_SYSLOG, LOG_DAEMON, "ucentral-event");
	avl_init(&subscribers, avl_intcmp, false, NULL);
	config_load();
	uloop_init();
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);
	uloop_run();
	uloop_done();
	ubus_auto_shutdown(&conn);

	return 0;
}
