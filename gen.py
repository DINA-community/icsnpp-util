import sys
import asn1tools
import inspect

type_mapping = [
    (["INTEGER", "ENUMERATED"], "int"),
    (["BOOLEAN", "NULL"], "bool"),
    (["REAL"], "double"),
    (
        [
            "OCTET STRING", "ANY", "OBJECT IDENTIFIER", "VisibleString", "UTF8String", "PrintableString",
            "GraphicString", "ObjectDescriptor", "T61String", "UTCTime", "IA5String"
        ],
        "string"
    ),
]

def map_type(type_id):
    """
    Returns the internal Zeek/C++ type for an ASN.1 type
    """
    m = [dest for src, dest in type_mapping if type_id in src]
    return m[0] if len(m) == 1 else None

def is_primitive_type(type_id, module, checkChild=True):
    """
    Determines whether a type is primitive in the mapped domain.
    """
    flat_types = [t for ts, _ in type_mapping for t in ts]
    return (type_id in flat_types) or (
        checkChild and type_id in module and is_primitive_type(module[type_id].get("type"), module, False)
    )

def is_special_type(type_id):
    """
    Checks for composite ASN.1 types.
    """
    return type_id in {"CHOICE", "SEQUENCE", "SEQUENCE OF"}

def indent(s, depth=1):
    """
    Indents every line in s by 'depth' levels.
    """
    prefix = "  " * depth
    return "\n".join(prefix + l for l in s.split("\n"))

def get_type_def(type_name, moduleName, asn1, search_global=True, force_module_name=False):
    """
    Looks up a type definition, possibly recursively through imports.
    """
    module = asn1[moduleName]
    typeDef = module["types"].get(type_name, None)
    if typeDef:
        return type_name, moduleName, typeDef
    if search_global:
        for foreign_module, imports in module["imports"].items():
            if type_name in imports:
                return get_type_def(type_name, foreign_module, asn1, False, True)
    return None, None, None

def get_type_id(type_name, moduleName, asn1, search_global=True, force_module_name=False):
    t, _, _ = get_type_def(type_name, moduleName, asn1, search_global, force_module_name)
    return t if t else None

def walk(typeName, typeDef, moduleName, asn1, follow_link, func, **params):
    """
    Recursively traverses ASN.1 types, applying 'func'.
    """
    visited = []

    def step(typeName, moduleName, typeDef):
        if not typeDef or "type" not in typeDef:
            return []
        module = asn1[moduleName]["types"]
        type_id = typeDef["type"]

        already_visited = type_id in visited and type_id in module
        visited.append(type_id)

        res = []
        if not already_visited:
            if type_id in ["SEQUENCE", "SET", "CHOICE"]:
                res = sum((step(typeName, moduleName, m) for m in typeDef["members"]), [])
            elif type_id in ["SEQUENCE OF", "SET OF"]:
                res = step(typeName, moduleName, typeDef["element"])
            elif follow_link:
                res = step(*get_type_def(type_id, moduleName, asn1))

        func_params = inspect.signature(func).parameters
        myparams = {
            name: value for name, value in vars().items()
            if name in ["typeName", "typeDef", "moduleName", "module", "asn1", "already_visited"]
            and name in func_params
        }
        res += [func(**(myparams | params))]
        return res

    return step(typeName, moduleName, typeDef)

def get_dependencies(typeName, moduleName, asn1, follow_links=True):
    """
    Returns all direct and indirect type dependencies of the given type.
    """
    return walk(typeName, asn1[moduleName]["types"][typeName], moduleName, asn1, follow_links, lambda typeDef: typeDef["type"])

def is_self_dependent(typeName, moduleName, asn1):
    """
    Returns True iff the ASN.1 type is self-referential (recursive).
    """
    complex_types = {"SEQUENCE", "SET", "CHOICE"}
    if not any(dep in complex_types for dep in get_dependencies(typeName, moduleName, asn1, False)):
        return False

    return any(
        walk(
            typeName, asn1[moduleName]["types"][typeName],
            moduleName, asn1, True,
            lambda typeDef: typeDef["type"] == typeName
        )
    )

# ==== ZEEK DECLARATIONS ====

def zeek_field_name(name):
    name = name.replace("-", "_")
    # avoid Zeek keywords
    zeek_keywords = {
        "output", "rename", "file", "timeout", "event",
        "domain", "cancel", "type"
    }
    return ("_" + name) if name in zeek_keywords else name

def zeek_enum_name(fieldName, typeName, module, force_qualified_name=False):
    """
    Returns a unique Zeek enum name for a given enum value.
    """
    def contains_field(typeDef):
        if not typeDef or "type" not in typeDef:
            return False
        type_id = typeDef["type"]
        if type_id in {"SEQUENCE", "SET", "CHOICE"}:
            return any(contains_field(m) for m in typeDef["members"])
        elif type_id in {"SEQUENCE OF", "SET OF"}:
            return contains_field(typeDef["element"])
        elif type_id == "BIT STRING" and fieldName in [x[0] for x in typeDef.get("named-bits", [])]:
            return True
        elif type_id == "INTEGER" and fieldName in typeDef.get("named-numbers", []):
            return True
        elif type_id == "ENUMERATED" and fieldName in [n[0] for n in typeDef.get("values", []) if n]:
            return True
        return False

    occurrences = sum(
        1 for typeNameTest in module if contains_field(module[typeNameTest])
    )
    prefix = zeek_field_name(typeName) + "_" if (occurrences > 1 or force_qualified_name) else ""
    return prefix + zeek_field_name(fieldName)

def create_zeek_var_decl(typeDef, typeName, moduleName, asn1, is_redef=False, depth=0):
    """
    Returns Zeek field declarations for an ASN.1 field.
    """
    type_id = typeDef["type"]
    module = asn1[moduleName]["types"]
    res = []
    if type_id in {"SEQUENCE", "SET", "CHOICE"}:
        res.append("{" if is_redef else "record {")
        for m in typeDef["members"]:
            if not m:
                continue
            is_optional = type_id == "CHOICE" or is_redef or m.get("optional", False)
            res.append(
                "  " * (depth + 1)
                + zeek_field_name(m["name"])
                + ": "
                + create_zeek_var_decl(m, typeName, moduleName, asn1, False, depth + 1)
                + (" &optional" if is_optional else "") + ";"
            )
        res.append("  " * depth + "}")
    elif type_id in {"SEQUENCE OF", "SET OF"}:
        res.append(
            ("vector of " if not is_redef else "")
            + create_zeek_var_decl(typeDef["element"], typeName, moduleName, asn1, is_redef, depth)
        )
    elif type_id == "BIT STRING":
        if "named-bits" in typeDef:
            res += ["vector of enum {"] + [
                "  " * (depth + 1) + zeek_enum_name(b[0], typeName, module) + ","
                for b in typeDef["named-bits"]
            ] + ["}"]
        else:
            res.append("string")
    elif type_id == "INTEGER" and "named-numbers" in typeDef:
        res += ["enum {"] + [
            "  " * (depth + 1) + zeek_enum_name(n, typeName, module) + f" = {v},"
            for n, v in typeDef["named-numbers"].items()
        ] + ["  " * depth + "}"]
    elif type_id == "ENUMERATED":
        res += ["enum {"] + [
            "  " * (depth + 1) + zeek_enum_name(item[0], typeName, module) + f" = {item[1]},"
            for item in typeDef["values"] if item
        ] + ["  " * depth + "}"]
    else:
        mapped_type = [dest for src, dest in type_mapping if type_id in src]
        if mapped_type:
            typename = mapped_type[0]
        else:
            typename = get_type_id(type_id, moduleName, asn1)
        res.append(zeek_field_name(typename))
    return "\n".join(res)

def create_zeek_type(typeName, moduleName, asn1, as_redef=False):
    module = asn1[moduleName]
    typeId, _, typeDef = get_type_def(typeName, moduleName, asn1)
    zeekType = "enum" if typeDef["type"] == "BIT STRING" else "record"
    zeekTypeName = zeek_field_name(get_type_id(typeId, moduleName, asn1))
    if as_redef:
        return f"redef record {zeekTypeName} += {create_zeek_var_decl(typeDef, typeId, moduleName, asn1, True)};\n"
    else:
        return f"type {zeekTypeName}: {create_zeek_var_decl(typeDef, typeId, moduleName, asn1, False)};\n"

def get_subtypes(typeDef, module, visited=None):
    if visited is None:
        visited = []
    if not typeDef:
        return []
    type_id = typeDef["type"]
    if type_id in visited:
        return []
    if type_id in {"SEQUENCE", "CHOICE"}:
        return sum([get_subtypes(s, module, visited) for s in typeDef["members"]], [])
    elif type_id == "SEQUENCE OF":
        return get_subtypes(typeDef["element"], module, visited)
    elif type_id in module:
        return get_subtypes(module[type_id], module, visited + [type_id]) + [type_id]
    else:
        return []

def create_zeek_types(mainModuleName, asn1):
    types = {}
    self_dependent_decl = []
    self_dependent_redef = []
    decl = []
    primitive_decl = []

    for moduleName in asn1:
        module = asn1[moduleName]["types"]
        self_dependent_types = [typeName for typeName in module if is_self_dependent(typeName, moduleName, asn1)]

        for typeName in module:
            types[typeName] = create_zeek_type(typeName, moduleName, asn1, typeName in self_dependent_types)

        # Zeek doesn't support forward declarations. 
        # We must therefore define all data types before they are used.
        typeNames = list(types.keys())
        for typeName in typeNames:
            deps = get_dependencies(typeName, moduleName, asn1) + [typeName]
            for d in deps:
                if d in types:
                    if d in self_dependent_types:
                        self_dependent_decl.append(f"type {d}: record {{}};")
                        self_dependent_redef.append(types[d])
                    elif is_primitive_type(d, module):
                        primitive_decl.append(types[d])
                    else:
                        decl.append(types[d])
                    del types[d]

    if self_dependent_decl:
        self_dependent_decl.insert(0, "\n# ======== FORWARD DECLARATIONS =======")
        self_dependent_redef.insert(0, "\n# ======== SELF DEPENDENT TYPES =======")
    if primitive_decl:
        primitive_decl.insert(0, "\n# ======== PRIMITIVE TYPES =======")
    if decl:
        decl.insert(0, "\n# ======== COMPLEX TYPES =======")

    res = [
        "#THIS CODE IS GENERATED. DON'T CHANGE MANUALLY!",
        f"module {zeek_field_name(mainModuleName).lower()};",
        "export {",
        indent("\n".join(primitive_decl + self_dependent_decl + decl + self_dependent_redef)),
        "}"
    ]
    return "\n".join(res)

# ==== C++ PROCESSOR ====

def c_field_name(name):
    if name == "unsigned":
        return "Unsigned"
    return "".join([c if c.isalnum() or c == "_" else "_" for c in name])

def processor_signature(type_id):
    t = c_field_name(type_id)
    return f"IntrusivePtr<Val> process_{t}(const {t}_t* src)"

def create_processor_top(typeName, moduleName, module):
    return processor_signature(typeName) + "{" + create_processor(module[typeName], moduleName, module, typeName) + " return res;}"

def create_type(typeName, typeDef, moduleName, module):
    ctype = "VectorType" if typeDef["type"] in ["SEQUENCE OF", "SET OF", "BIT STRING"] else "RecordType"
    if typeName in module:
        fieldname = zeek_field_name(moduleName).lower() + "::" + zeek_field_name(typeName)
        return f'static const auto type = id::find_type<{ctype}>("{fieldname}");'
    else:
        res = f"static const auto type=get_field_type<{ctype}>(container"
        if "name" in typeDef:
            fieldname = zeek_field_name(typeDef['name'])
            res += f', "{fieldname}"'
        return res + ");"

def get_default_value(typeName, moduleName, typeDef, asn1, default=None):
    type_id = typeDef["type"]
    if default is None:
        default = typeDef["default"]
    if type_id == "BOOLEAN":
        # Booleans are stored as ints by asn1c
        return "1" if default else "0"
    if type_id == "INTEGER":
        return default
    if type_id == "BIT STRING":
        # default values for bit strings are processed separately
        return None
    else:
        typeName, moduleName, typeDef = get_type_def(type_id, moduleName, asn1)
        if not typeDef:
            raise Exception(f"default values for {type_id} not implemented")
        return get_default_value(typeName, moduleName, typeDef, asn1, default)

def create_processor(typeDef, moduleName, module, typeId=None):
    type_id = typeDef["type"]

    # Ref to named type
    if type_id in module and module[type_id]["type"] not in ["CHOICE", "SEQUENCE", "SET", "SEQUENCE OF", "SET OF", "BIT STRING"]:
        return create_processor(module[type_id], moduleName, module, typeId)

    if type_id in {"CHOICE", "SEQUENCE", "SET"}:
        if not any(typeDef["members"]):
            return ""
        get_type = create_type(typeId, typeDef, moduleName, module)
        res = f"""
            IntrusivePtr<Val> res;
            {{
                {get_type}
                const auto container=make_intrusive<RecordVal>(type);
        """
        for m in typeDef["members"]:
            if not m:
                continue
            if typeDef["type"] == "CHOICE":
                src = f"src->choice.{c_field_name(m['name'])}"
                fieldname_c = c_field_name(typeId + "_PR_" + m['name'])
                if "__Member__" in fieldname_c:
                    fieldname_c=fieldname_c.split("__Member__")[-1]
                cond = f"src->present=={fieldname_c}"
            else:
                src = f"src->{c_field_name(m['name'])}"
                cond = src if m.get("optional", False) and "default" not in m else None
            guard = f"if({cond})" if cond else ""

            fieldname_bro = zeek_field_name(m["name"])

            default = ""
            if "default" in m:
                defaultValue = get_default_value(None, moduleName, m, asn1)
                if defaultValue:
                    default = f"const auto default_value={defaultValue};"
                    src = f"{src} ? {src} : &default_value"
            src_ptr = f"ptr({src})"
            subtype = f"{typeId}__{m['name']}"
            content = create_processor(m, moduleName, module, subtype)
            if content:
                res += f"""
                    {guard}
                    {{  {default}
                        const auto _new_src={src_ptr};
                        const auto src=_new_src;
                        {content}
                        container->AssignField("{fieldname_bro}", res);
                    }}
                """
        res += """
            res = container;
            }
        """
        return res
    elif type_id in ["SEQUENCE OF", "SET OF"]:
        get_type = create_type(typeId, typeDef, moduleName, module)
        content = create_processor(typeDef["element"], moduleName, module, typeId + "__Member")
        return f"""
            IntrusivePtr<Val> res;
            {{
                {get_type}
                const auto container=make_intrusive<VectorVal>(type);
                for(int i=0; i<src->list.count; i++) {{
                    const auto _new_src=src->list.array[i];
                    const auto src=_new_src;
                    {content}
                    container->Append(res);
                }}
                res = container;
            }}
        """
    elif type_id == "NULL":
        return "const auto res=true;"
    elif type_id == "BIT STRING":
        if "named-bits" in typeDef:
            res = create_type(typeId, typeDef, moduleName, module) + f"""
                    static IntrusivePtr<EnumType> enum_type=nullptr;
                    if(!enum_type) {{
                        auto subtype=type->Yield();
                        if(!subtype || subtype->Tag() != TYPE_ENUM)
                            reporter->InternalError(
                                "Unable to process '{typeId}': "
                                "%s is not a vector of enums",
                                type->GetName().c_str()
                            );
                        enum_type = cast_intrusive<EnumType>(subtype);
                    }}
                    auto res = make_intrusive<VectorVal>(type);
                """
            for bitname, bitpos in typeDef["named-bits"]:
                default_value = "true" if bitname in typeDef.get("default", []) else "false"
                res += (
                    f"if(src ? is_bit_set(src, {bitpos}) : {default_value})"
                    f" /* {bitname} */ res->Append(enum_type->GetEnumVal({bitpos}));\n"
                )
            return res
        else:
            return "const auto res=convert(src);"
    elif is_primitive_type(type_id, module):
        return "const auto res=convert(src);"
    else:
        return f"const auto res=process_{c_field_name(type_id)}(src);"

def create_cpp_code(moduleName, asn1, cpp_namespace):
    complex_types = [
        (typeName, moduleName)
        for moduleName in asn1
        for typeName in asn1[moduleName]["types"]
        if not is_primitive_type(typeName, asn1[moduleName]["types"])
    ]
    res = """/* THIS CODE IS GENERATED. DON'T CHANGE MANUALLY! */

        #include "zeek/Val.h"
        #include "process.h"

        #pragma GCC diagnostic ignored "-Wunused-variable"
        #pragma GCC diagnostic ignored "-Wunused-function"

        using namespace zeek;

        namespace {

        template <typename T>
        inline const T* ptr(const T* v) {return v;}

        template <typename T>
        inline typename std::enable_if<!std::is_pointer<T>::value, const T*>::type
        ptr(const T& v) {return &v;}

        inline IntrusivePtr<Val> convert(const int *i) { return make_intrusive<IntVal>(*i); }
        inline IntrusivePtr<Val> convert(const long int *i) { return make_intrusive<IntVal>(*i); }
        inline IntrusivePtr<Val> convert(const unsigned int *i) { return make_intrusive<IntVal>(*i); }
        inline IntrusivePtr<Val> convert(const long unsigned int *i) { return make_intrusive<IntVal>(*i); }

        #ifdef _OBJECT_IDENTIFIER_H_
        IntrusivePtr<Val> convert(const OBJECT_IDENTIFIER_t *oid) {
            std::string res;
            unsigned long arcs[100];
            int arc_slots=sizeof(arcs)/sizeof(arcs[0]);
            int count = OBJECT_IDENTIFIER_get_arcs(oid, arcs, sizeof(arcs[0]), arc_slots);
            if(count<0 || count>arc_slots)
                return nullptr;
            for(int i=0; i<count; i++) {
                if(i!=0)
                    res += ".";
                res += std::to_string(arcs[i]);
            }
            return make_intrusive<StringVal>(res);
        }
        #endif

        template <typename T>
        inline IntrusivePtr<Val> convert(const T *s) {
            return make_intrusive<StringVal>(s->size, reinterpret_cast<const char *>(s->buf));
        }

        bool is_bit_set(const BIT_STRING_t *s, unsigned int idx) {
            int byte_no=idx/8;
            if(byte_no >= s->size)
                return false;
            auto byte=s->buf[byte_no];
            return byte & (1<<(idx%8));
        }

        /* 
         * In the event of an error, the function does not return,
         * but deliberately causes a core dump.
         */
        template <typename T>
        IntrusivePtr<T> get_field_type(IntrusivePtr<RecordVal> container, const char* fieldname) {
            auto tag=TYPE_RECORD;
            if constexpr (std::is_same_v<T, VectorType>)
                tag=TYPE_VECTOR;
            auto container_type=cast_intrusive<RecordType>(container->GetType());
            if(!container_type->HasField(fieldname)) {
                reporter->InternalError(
                    "Unable to process '%s': Missing field '%s'",
                    container_type->GetName().c_str(), fieldname
                );
            }
            auto field_type=container_type->GetFieldType(fieldname);
            if(field_type->Tag() != tag) {
                reporter->InternalError(
                    "Unable to process '%s': Field '%s' is of wrong type",
                    container_type->GetName().c_str(), fieldname
                );
            }
            return cast_intrusive<T>(field_type);
        }

        template <typename T>
        IntrusivePtr<T> get_field_type(IntrusivePtr<VectorVal> container) {
            auto tag=TYPE_RECORD;
            if constexpr (std::is_same_v<T, VectorType>)
                tag=TYPE_VECTOR;
            auto subtype=container->GetType()->Yield();
            if(!subtype || subtype->Tag() != tag) {
                reporter->InternalError(
                    "Unable to process '%s': Content is of wrong type",
                    container->GetType()->GetName().c_str()
                );
            }
            return cast_intrusive<T>(subtype);
        }
    }

    """

    res += f"namespace {cpp_namespace} {{\n\n"
    for t, m in complex_types:
        res += create_processor_top(t, m, asn1[m]["types"]) + "\n\n"
    return res + "\n\n}"

def create_hpp_code(moduleName, asn1, cpp_namespace):
    complex_types = [
        typeName
        for moduleName in asn1
        for typeName in asn1[moduleName]["types"]
        if not is_primitive_type(typeName, asn1[moduleName]["types"])
    ]
    res = """/* THIS CODE IS GENERATED. DON'T CHANGE MANUALLY! */

        #pragma once

        #include "zeek/Val.h"
    """
    for t in complex_types:
        res += f"#include <{t}.h>\n"

    res += f"""
        using namespace zeek;

        namespace {cpp_namespace} {{\n
    """
    for t in complex_types:
        res += processor_signature(t) + ";"
    return res + "\n\n}"

if __name__ == "__main__":
    if len(sys.argv) < 4 or sys.argv[1] not in ["zeek", "cpp", "hpp"]:
        print("USAGE gen.py zeek moduleName file1 file2 ...\n      gen.py [cpp|hpp] moduleName cppNamespace file1 file2 ...")
        sys.exit(1)

    moduleName = sys.argv[2]

    if sys.argv[1] == "zeek":
        asn1 = asn1tools.parse_files(sys.argv[3:])
        print(create_zeek_types(moduleName, asn1))
    else:
        asn1 = asn1tools.parse_files(sys.argv[4:])
        if sys.argv[1] == "cpp":
            print(create_cpp_code(moduleName, asn1, sys.argv[3].lower()))
        else:
            print(create_hpp_code(moduleName, asn1, sys.argv[3].lower()))
