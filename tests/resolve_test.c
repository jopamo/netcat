#include "resolve.h"
#include "nc_ctx.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

static void test_single_port_parsing(void) {
    struct nc_ctx ctx;
    nc_ctx_init(&ctx);

    assert(nc_parse_port_range(&ctx, "1234") == 0);
    assert(ctx.loport == 1234);
    assert(ctx.hiport == 1234);
    assert(ctx.curport == 1234);
    assert(ctx.single_mode);
    assert(ctx.port_num == 1234);
    assert(ctx.port_name[0] != '\0');

    nc_ctx_cleanup(&ctx);
}

static void test_range_parsing_swaps_and_tracks_bounds(void) {
    struct nc_ctx ctx;
    nc_ctx_init(&ctx);

    assert(nc_parse_port_range(&ctx, "6000-5000") == 0);
    assert(ctx.loport == 5000);
    assert(ctx.hiport == 6000);
    assert(ctx.curport == 6000);
    assert(!ctx.single_mode);

    nc_ctx_cleanup(&ctx);
}

static void test_invalid_port_rejected(void) {
    struct nc_ctx ctx;
    nc_ctx_init(&ctx);

    assert(nc_parse_port_range(&ctx, "0") < 0);

    nc_ctx_cleanup(&ctx);
}

static void test_random_port_iteration_exhausts_range(void) {
    struct nc_ctx ctx;
    nc_ctx_init(&ctx);

    srand(1);
    assert(nc_random_ports_init(&ctx, 1000, 1003) == 0);

    bool seen[4] = {false, false, false, false};
    for (size_t i = 0; i < 4; i++) {
        unsigned short p = nc_random_ports_next(&ctx);
        assert(p >= 1000);
        assert(p <= 1003);
        size_t idx = (size_t)(p - 1000);
        assert(!seen[idx]);
        seen[idx] = true;
    }

    assert(nc_random_ports_next(&ctx) == 0);
    for (size_t i = 0; i < 4; i++)
        assert(seen[i]);

    nc_ctx_cleanup(&ctx);
}

int main(void) {
    test_single_port_parsing();
    test_range_parsing_swaps_and_tracks_bounds();
    test_invalid_port_rejected();
    test_random_port_iteration_exhausts_range();
    return 0;
}
