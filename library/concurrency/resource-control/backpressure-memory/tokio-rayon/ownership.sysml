package BackpressureOwnership {
    private import ScalarValues::*;
    part def Ownership {
        attribute live : Integer;
        attribute reserved : Integer;
        assert constraint retainedRequiresReservation { live == reserved }
    }
}
