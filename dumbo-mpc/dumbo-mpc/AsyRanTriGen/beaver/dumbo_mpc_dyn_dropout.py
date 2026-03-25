from beaver.dumbo_mpc_dyn import BEAVER as FullBEAVER


class BEAVER(FullBEAVER):
    """Dropout experiment: two honest nodes skip epoch/layer 4 (L==3)."""

    def _should_skip_layer(self, layer_idx):
        return layer_idx == 3 and self.my_id in (0, 1)
