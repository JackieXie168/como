#include <assert.h>

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

typedef MonoObject * (*to_mono_fn) (MonoDomain * domain, MonoImage * image,
				    void * ref);

typedef struct proxy_mono_state {
    MonoDomain *	domain;
    MonoAssembly *	assembly;
    MonoImage *		image;
    MonoObject *	mdl;
    to_mono_fn		config_to_mono;
    to_mono_fn		tuple_to_mono;
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

int
proxy_mono_load(mdl_t * mdl)
{
    proxy_mono_state_t *s;
    const char *libdir;
    char *filename, *ns;
    mdl_ibase_t *ib;
    MonoClass *klass;
    MonoClassField *field;
    MonoString *str;
    
    s = como_new(proxy_mono_state_t);

    ib = mdl->priv;

    s->config_to_mono = get_to_mono(ib->shobj, "config_type");
    if (s->config_to_mono == NULL) {
	free(s);
	return -1;
    }
    
    s->tuple_to_mono = get_to_mono(ib->shobj, "tuple_type");
    if (s->tuple_to_mono == NULL) {
	free(s);
	return -1;
    }
    
    s->domain = mono_jit_init(mdl->name);
    if (s->domain == NULL) {
	warn("mono_jit_init() failed.\n");
	free(s);
	return -1;
    }
    
    mono_add_internal_call("CoMo.Mdl::mdl_store_rec", mdl_store_mono_rec);
    
    libdir = como_env_libdir();
    filename = como_asprintf("%s/%s.dll", libdir, mdl->mdlname);
    
    s->assembly = mono_domain_assembly_open(s->domain, filename);
    if (s->assembly == NULL) {
	warn("mono_domain_assembly_open() failed.\n");
	free(filename);
	free(s);
	return -1;
    }
    free(filename);
    
    s->image = mono_assembly_get_image(s->assembly);
    if (s->assembly == NULL) {
	warn("mono_assembly_get_image() failed.\n");
	free(s);
	return -1;
    }
    
    ns = como_asprintf("CoMo.Modules.%s", mdl->mdlname);
    
    klass = mono_class_from_name(s->image, ns, "Export");
    if (klass == NULL) {
	warn("mono_class_from_name() failed.\n");
	free(ns);
	free(s);
	return -1;
    }
    free(ns);

    /* construct the object */
    s->mdl = mono_object_new(s->domain, klass);
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
    field = mono_class_get_field_from_name(klass, "mdl");
    mono_field_set_value(s->mdl, field, &mdl);

    field = mono_class_get_field_from_name(klass, "flush_ivl");
    mono_field_set_value(s->mdl, field, &mdl->flush_ivl);

    field = mono_class_get_field_from_name(klass, "name");
    str = mono_string_new(s->domain, mdl->name);
    mono_field_set_value(s->mdl, field, str);

    if (mdl->description) {
	field = mono_class_get_field_from_name(klass, "description");
	str = mono_string_new(s->domain, mdl->description);
	mono_field_set_value(s->mdl, field, str);
    }

    if (mdl->filter) {
	field = mono_class_get_field_from_name(klass, "filter");
	str = mono_string_new(s->domain, mdl->filter);
	mono_field_set_value(s->mdl, field, str);
    }

    field = mono_class_get_field_from_name(klass, "mdlname");
    str = mono_string_new(s->domain, mdl->mdlname);
    mono_field_set_value(s->mdl, field, str);

    field = mono_class_get_field_from_name(klass, "streamsize");
    mono_field_set_value(s->mdl, field, &mdl->streamsize);

    mdl->priv->proc.ex->state = s;
    
    return 0;
}

void *
proxy_mono_ex_init(mdl_t * mdl)
{
    proxy_mono_state_t *s;
    MonoClass *klass;
    MonoClassField *field;
    MonoMethod *method;
    MonoObject *config;

    s = (proxy_mono_state_t *) mdl->priv->proc.ex->state;
    
    klass = mono_object_get_class(s->mdl);
    

    /* create an object for the module config */

    config = s->config_to_mono(s->domain, s->image, mdl->config);
    if (config == NULL) {
	warn("config_to_mono() failed.\n");
	free(s);
	return NULL;
    }

    field = mono_class_get_field_from_name(klass, "config");
    mono_field_set_value(s->mdl, field, config);


    /* invoke ex_init() */
    method = mono_class_get_method_from_name(klass, "ex_init", -1);
    assert(method != NULL);
    
    mono_runtime_invoke(method, s->mdl, NULL, NULL);
    
    return s;
}


void
proxy_mono_export(UNUSED mdl_t * mdl, void ** tuples, size_t ntuples,
		  timestamp_t ivl_start, void * state)
{
    proxy_mono_state_t *s;
    MonoClass *klass;
    MonoMethod *method;
    MonoArray *tuples_array;
    size_t i;
    void *args[2];
    
    s = (proxy_mono_state_t *) state;

    klass = mono_object_get_class(s->mdl);

    tuples_array = mono_array_new(s->domain, mono_get_object_class(), ntuples);

    for (i = 0; i < ntuples; i++) {
	MonoObject *t;
	t = s->tuple_to_mono(s->domain, s->image, tuples[i]);
	if (t == NULL) {
	    error("tuple_to_mono() failed.\n");
	}
	mono_array_set(tuples_array, MonoObject *, i, t);
    }
    
    args[0] = tuples_array;
    args[1] = &ivl_start;
    
    /* invoke export() */
    method = mono_class_get_method_from_name(klass, "export", -1);
    assert(method != NULL);
    
    mono_runtime_invoke(method, s->mdl, args, NULL);
}


