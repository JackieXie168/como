#include "como.h"

como_tuple struct traffic_tuple {
    timestamp_t ts;
    double      bytes[2];
    double      pkts[2];
};

como_record struct traffic_record {
    timestamp_t ts;
    uint64_t    bytes[2];
    uint32_t    pkts[2];
};

como_config struct traffic_config {
    int meas_ivl;	/* measurement interval */
    int iface;		/* interface */
};

typedef struct traffic_tuple tuple_t;
typedef struct traffic_record record_t;
typedef struct traffic_config config_t;

#define FLOWDESC struct traffic_tuple

