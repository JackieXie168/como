#include <assert.h>
#include <stdlib.h>

#include <mono/jit/jit.h>
#include <mono/metadata/assembly.h>
/*
#include <mono/metadata/object.h>
#include <mono/metadata/environment.h>
#include <mono/metadata/debug-helpers.h>
*/

#include "como.h"
#include "comopriv.h"
#include "storage.h"

/*
 * This file provides the C callbacks the core expects from
 * modules, and translates the calls to calls to the mono
 * objects.
 *
 * The idea is that the core does not need to know about mono,
 * but just about C modules.
 */

typedef MonoObject * (*to_mono_fn) (MonoDomain * domain, MonoImage * image,
				    void * ref);

typedef struct proxy_mono_state {
    MonoDomain *	domain;
    MonoAssembly *	assembly;
    MonoImage *		image;
    MonoObject *	mdl;
    MonoClass *         klass;

    to_mono_fn		config_to_mono;
    to_mono_fn		tuple_to_mono;
    to_mono_fn		record_to_mono;
    char *              ns;

    /* only for export */
    MonoMethod *        ex_init;
    MonoMethod *        ex_export;

    /* only for query */
    MonoMethod *        qu_init;
    MonoMethod *        qu_print_rec;
    MonoMethod *        qu_finish;
    MonoString *        format_monostring;
} proxy_mono_state_t;


static void
mdl_store_mono_rec(mdl_t * mdl, MonoArray * data)
{
    mdl_iexport_t *ie;
    size_t sz;
    uint8_t *st;
    uint8_t *rec;
    
    sz = mono_array_length(data);
    rec = mono_array_addr(data, uint8_t, 0);
    
    /* the timestamp is the first 64-bit integer of the record */
#if DEBUG
    timestamp_t ts;
    ts = *((timestamp_t *) rec);
    debug("mdl_store_mono_rec: mdl = `%s' ts = %u\n", mdl->name, TS2SEC(ts));
#endif

    ie = mdl_get_iexport(mdl);

    sz = sz + sizeof(size_t);

    st = (uint8_t *) csmap(ie->cs_writer, ie->woff, (ssize_t *) &sz);
    if (st == NULL)
	error("csmap() failed for module `%s'\n", mdl->name);

    if ((ssize_t) sz == -1)
	error("Can't write to disk for module `%s'\n", mdl->name);

    serialize_uint32_t(&st, sz);
    memcpy(st, rec, sz);

    ie->woff += sz;
    cscommit(ie->cs_writer, ie->woff);
}

static void
mdl_mono_print(mdl_t *mdl, MonoString *string)
{
    char *str = mono_string_to_utf8(string);
    mdl_printf(mdl, "%s", str);
}

MonoString *
mono_inet_ntoa(int addr)
{
    char buffer[128];

    struct in_addr in;
    in.s_addr = addr;
    sprintf(buffer, "%s", inet_ntoa(in));

    return mono_string_new(mono_domain_get(), buffer);
}

static to_mono_fn
get_to_mono(shobj_t * shobj, const char * type)
{
    void *sym;
    char *structname;
    char *funcname;

    sym = shobj_symbol(shobj, type, FALSE);
    if (sym == NULL) {
        return NULL;
    }
    structname = *((char **) sym);
    
    funcname = como_asprintf("to_mono_%s", structname);

    sym = shobj_symbol(shobj, funcname, FALSE);
    free(funcname);
    return (to_mono_fn) sym;
}

static proxy_mono_state_t *
proxy_mono_load(mdl_t * mdl, char *class_name)
{
    proxy_mono_state_t *s;
    const char *libdir;
    char *filename;
    mdl_ibase_t *ib;
    MonoClassField *field;
    MonoString *str;
    
    s = como_new(proxy_mono_state_t);

    ib = mdl->priv;

    s->config_to_mono = get_to_mono(ib->shobj, "config_type");
    if (s->config_to_mono == NULL) {
        warn("module `%s': internal error - config_type_to_mono() missing\n",
                mdl->name);
	free(s);
	return NULL;
    }
    
    s->tuple_to_mono = get_to_mono(ib->shobj, "tuple_type");
    if (s->tuple_to_mono == NULL) {
        warn("module `%s': internal error - tuple_type_to_mono() missing\n",
                mdl->name);
	free(s);
	return NULL;
    }

    s->record_to_mono = get_to_mono(ib->shobj, "record_type");
    if (s->record_to_mono == NULL) {
        warn("module `%s': internal error - record_type_to_mono() missing\n",
                mdl->name);
        free(s);
        return NULL;
    }

    s->domain = mono_jit_init(mdl->name);
    if (s->domain == NULL) {
	warn("mono_jit_init() failed.\n");
	free(s);
	return NULL;
    }
    
    mono_add_internal_call("CoMo.Mdl::mdl_store_rec", mdl_store_mono_rec);
    mono_add_internal_call("CoMo.Mdl::mdl_print", mdl_mono_print);
    mono_add_internal_call("CoMo.IP::to_string", mono_inet_ntoa);
    
    libdir = como_env_libdir();
    filename = como_asprintf("%s/%s.dll", libdir, mdl->mdlname);
    
    s->assembly = mono_domain_assembly_open(s->domain, filename);
    free(filename);
    if (s->assembly == NULL) {
	warn("mono_domain_assembly_open(%s.dll) failed.\n", mdl->name);
	free(s);
	return NULL;
    }
    debug("loaded mdl assembly\n");

    s->image = mono_assembly_get_image(s->assembly);
    if (s->assembly == NULL) {
	warn("mono_assembly_get_image(mdl) failed.\n");
	free(s);
	return NULL;
    }
    debug("loaded mdl image\n");

    s->ns = como_asprintf("CoMo.Modules.%s", mdl->mdlname);
    
    s->klass = mono_class_from_name(s->image, s->ns, class_name);
    if (s->klass == NULL) {
	warn("mono_class_from_name(\"%s\", \"%s\") failed.\n", s->ns, class_name);
	free(s->ns);
	free(s);
	return NULL;
    }
    debug("locate mdl mono class %s\n", class_name);

    /* construct the object */
    s->mdl = mono_object_new(s->domain, s->klass);
    mono_runtime_object_init(s->mdl);
    
/*
	IntPtr mdl;
	ulong flush_ivl;
	string name;
	string description;
	string filter;
	string mdlname;
	ulong streamsize;
	object config;
*/
    /* set the fields */
    debug("setting fields\n");
    field = mono_class_get_field_from_name(s->klass, "mdl");
    mono_field_set_value(s->mdl, field, &mdl);

    field = mono_class_get_field_from_name(s->klass, "flush_ivl");
    mono_field_set_value(s->mdl, field, &mdl->flush_ivl);

    field = mono_class_get_field_from_name(s->klass, "name");
    str = mono_string_new(s->domain, mdl->name);
    mono_field_set_value(s->mdl, field, str);

    if (mdl->description) {
	field = mono_class_get_field_from_name(s->klass, "description");
	str = mono_string_new(s->domain, mdl->description);
	mono_field_set_value(s->mdl, field, str);
    }

    if (mdl->filter) {
	field = mono_class_get_field_from_name(s->klass, "filter");
	str = mono_string_new(s->domain, mdl->filter);
	mono_field_set_value(s->mdl, field, str);
    }

    field = mono_class_get_field_from_name(s->klass, "mdlname");
    str = mono_string_new(s->domain, mdl->mdlname);
    mono_field_set_value(s->mdl, field, str);

    field = mono_class_get_field_from_name(s->klass, "streamsize");
    mono_field_set_value(s->mdl, field, &mdl->streamsize);

    return s;
}

static int
proxy_mono_check_implements(MonoClass *klass, char *wanted_iface)
{
    MonoClass *iface;
    gpointer iter = NULL;

    while ((iface = mono_class_get_interfaces (klass, &iter)))
        if (!strcmp(mono_class_get_name(iface), wanted_iface))
            return 0; 
    
    return -1;
}

int
proxy_mono_load_export(mdl_t *mdl)
{
    proxy_mono_state_t *s;
    mdl_get_iexport(mdl)->state = s = proxy_mono_load(mdl, "Export");

    if (s == NULL)
        return -1;
    if (proxy_mono_check_implements(s->klass, "IExport") == -1) {
        warn("module `%s': class Export must implement IExport!");
        return -1;
    }

    s->ex_init = mono_class_get_method_from_name(s->klass, "init", -1);
    s->ex_export = mono_class_get_method_from_name(s->klass, "export",-1);

    assert(s->ex_init != NULL);
    assert(s->ex_export != NULL);

    debug("mono module `%s' loaded.\n", mdl->name);
    return 0;
}

int
proxy_mono_load_query(mdl_t *mdl)
{
    proxy_mono_state_t *s;
    mdl_get_iquery(mdl)->state = s = proxy_mono_load(mdl, "Query");
    if (s == NULL)
        return -1;
    if (proxy_mono_check_implements(s->klass, "IQuery") == -1) {
        warn("module `%s': class Query must implement IQuery!");
        return -1;
    }

    s->qu_init = mono_class_get_method_from_name(s->klass, "init", -1);
    s->qu_print_rec = mono_class_get_method_from_name(s->klass, "print_rec",-1);
    s->qu_finish = mono_class_get_method_from_name(s->klass, "finish", -1);

    assert(s->qu_init != NULL);
    assert(s->qu_print_rec != NULL);
    assert(s->qu_finish != NULL);

    return 0;
}

void *
proxy_mono_ex_init(mdl_t * mdl)
{
    proxy_mono_state_t *s;
    MonoClassField *field;
    MonoObject *config;


    s = mdl_get_iexport(mdl)->state;

    /* create an object for the module config */

    config = s->config_to_mono(s->domain, s->image, mdl->config);
    if (config == NULL) {
	warn("config_to_mono() failed.\n");
	free(s);
	return NULL;
    }

    field = mono_class_get_field_from_name(s->klass, "config");
    mono_field_set_value(s->mdl, field, config);

    /* invoke ex_init() */
    debug("module `%s': ex_init()\n", mdl->name);
    mono_runtime_invoke(s->ex_init, s->mdl, NULL, NULL);
    debug("module `%s': ex_inited\n", mdl->name);
    
    return s;
}

void *
proxy_mono_qu_init(mdl_t * mdl, int format_id, UNUSED hash_t * mdl_args)
{
    proxy_mono_state_t *s;
    MonoClassField *field;
    MonoObject *config;
    mdl_iquery_t *iq;
    MonoObject *hash;
    void *args[2];

    s = (proxy_mono_state_t *) mdl->priv->proc.qu->state;
    
    /* create an object for the module config */
    config = s->config_to_mono(s->domain, s->image, mdl->config);
    if (config == NULL) {
	warn("config_to_mono() failed.\n");
	free(s);
	return NULL;
    }

    field = mono_class_get_field_from_name(s->klass, "config");
    mono_field_set_value(s->mdl, field, config);

    /* prepare argument: format name */
    iq = mdl_get_iquery(mdl);
    s->format_monostring = mono_string_new(s->domain,
                                            iq->formats[format_id].name);
    /* prepare argument: args hash */
    warn("TODO: prepare args hash for query\n");
    hash = NULL;

    /* prepare argument list */
    args[0] = s->format_monostring;
    args[1] = hash;

    /* invoke qu_init() */
    mono_runtime_invoke(s->qu_init, s->mdl, args, NULL);
    
    return s;
}

/*
 * -- proxy_mono_get_formats
 *
 * Accesses the mono class to retrieve the supported
 * output formats of the module, and translates this
 * to information the core understands.
 */
qu_format_t *
proxy_mono_get_formats(mdl_t *mdl, char **dflt_format)
{
    static qu_format_t default_format_array[2] = {
        { 0, "plain", "text/plain" },
        {-1, NULL, NULL}
    };
    qu_format_t *formats;
    proxy_mono_state_t *s;
    MonoClassField *field;
    mdl_iquery_t *iq;

    iq = mdl_get_iquery(mdl);
    s = iq->state;

    debug("Loading formats for module `%s'\n", mdl->name);
    field = mono_class_get_field_from_name(s->klass, "formats");
    if (field == NULL) {
        warn("Module `%s': Supported formats list not available. Assuming "
                "plain text content-type.\n", mdl->name);
        *dflt_format = "plain";
        return default_format_array;
    } else {
        /* parse the value of the field 'formats' */
        MonoArray *arr;
        int i, l;

        mono_field_get_value(s->mdl, field, &arr);
        l = mono_array_length(arr);
        if (l == 0)
            error("module `%s': supported format array is empty!\n",
                mdl->name);
        debug("formats array len is %d\n", l);

        formats = como_calloc(l + 1, sizeof(qu_format_t));
        for (i = 0; i < l; i++) {
            MonoObject *o;
            MonoClass *c;
            MonoClassField  *field_name, *field_ct_type;
            MonoString *name_monostr, *ct_type_monostr;
            char *name, *ct_type;

            o = mono_array_get(arr, MonoObject *, i);
            c = mono_object_get_class(o);
            field_name = mono_class_get_field_from_name(c, "name");
            field_ct_type = mono_class_get_field_from_name(c, "content_type");
            mono_field_get_value(o, field_name, &name_monostr);
            mono_field_get_value(o, field_ct_type, &ct_type_monostr);
            name = mono_string_to_utf8(name_monostr);
            ct_type = mono_string_to_utf8(ct_type_monostr);

            debug("format name=`%s' content_type=`%s'\n", name, ct_type);
            formats[i].id = i;
            formats[i].name = name;
            formats[i].content_type = ct_type;
        }

        formats[l].id = -1;
        formats[l].name = NULL;
        formats[l].content_type = NULL;
    }

    field = mono_class_get_field_from_name(s->klass, "default_format");
    if (field == NULL) {
        warn("Module `%s': No default format specified. Assuming first: `%s'\n",
                mdl->name, formats[0].name);
        *dflt_format = formats[0].name;
    }

    return formats;
}

void
proxy_mono_export(UNUSED mdl_t * mdl, void ** tuples, size_t ntuples,
		  timestamp_t ivl_start, void * state)
{
    proxy_mono_state_t *s;
    MonoArray *tuples_array;
    size_t i;
    void *args[2];
    
    s = (proxy_mono_state_t *) state;
    tuples_array = mono_array_new(s->domain, mono_get_object_class(), ntuples);

    for (i = 0; i < ntuples; i++) {
	MonoObject *t;
	t = s->tuple_to_mono(s->domain, s->image, tuples[i]);
	if (t == NULL)
	    error("tuple_to_mono() failed.\n");
	mono_array_set(tuples_array, MonoObject *, i, t);
    }
    
    args[0] = tuples_array;
    args[1] = &ivl_start;
    
    /* invoke export() */
    debug("module `%s': export()ing\n", mdl->name);
    mono_runtime_invoke(s->ex_export, s->mdl, args, NULL);
    debug("module `%s': export()ed\n", mdl->name);
}

void
proxy_mono_qu_print_rec(mdl_t * mdl, UNUSED int format_id, void * record,
    UNUSED void * state)
{
    proxy_mono_state_t *s;
    void *args[2];

    s = mdl_get_iquery(mdl)->state;

    args[0] = s->format_monostring;
    args[1] = s->record_to_mono(s->domain, s->image, record);

    mono_runtime_invoke(s->qu_print_rec, s->mdl, args, NULL);
}

void
proxy_mono_qu_finish(mdl_t * mdl, UNUSED int format_id, UNUSED void * state)
{
    proxy_mono_state_t *s;
    void *args[1];

    s = (proxy_mono_state_t *) mdl_get_iquery(mdl)->state;
    args[0] = s->format_monostring;

    mono_runtime_invoke(s->qu_finish, s->mdl, args, NULL);
}

/*
 * -- proxy_mono_init
 *
 * Add/modify the MONO_PATH to como.dll
 */
void
proxy_mono_init(char *mono_path)
{
    char *np, *p = getenv("MONO_PATH");

    np = como_asprintf("%s%s%s", p ? p : "", p ? ":" : "", mono_path);
    setenv("MONO_PATH", np, 1);
}

