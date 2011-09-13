-record(attribute, {
    id              :: eradius_dict:attribute_id(),
    type = 'octets' :: eradius_dict:attribute_type(),
    name            :: string(),
    enc  = 'no'     :: 'no' | 'scramble' | 'salt_crypt'
}).

-record(vendor, {
    type :: eradius_dict:vendor_id(),
    name :: string()
}).

-record(value, {
    id   :: eradius_dict:value_id(),
    name :: string()
}).
