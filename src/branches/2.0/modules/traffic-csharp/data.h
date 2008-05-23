#include "como.h"

como_tuple como_record struct traffic_tuple {
    timestamp_t ts;
    uint64_t    bytes[2];
    uint32_t    pkts[2];
};

como_config struct traffic_config {
    int meas_ivl;	/* measurement interval */
    int iface;		/* interface */
};

typedef struct traffic_tuple tuple_t;
typedef struct traffic_config config_t;

