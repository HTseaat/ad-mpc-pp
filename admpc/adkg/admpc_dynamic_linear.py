from adkg.admpc_dynamic import ADMPC_Multi_Layer_Control
from adkg.admpc_dynamic import ADMPC_Dynamic as _BaseADMPCDynamic


class ADMPC_Dynamic(_BaseADMPCDynamic):
    GATE_MODE = "linear"

