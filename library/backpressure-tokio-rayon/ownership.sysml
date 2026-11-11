// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

package BackpressureOwnership {
    private import ScalarValues::*;
    part def Ownership {
        attribute live : Integer;
        attribute reserved : Integer;
        assert constraint retainedRequiresReservation { live == reserved }
    }
}
