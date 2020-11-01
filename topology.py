#############
# CONSTANTS #
#############
IGP_COSTS = {
    ("sin", "mrs"): 3, #10  # 10 580 km
    ("sin", "sjo"): 4, #13  # 13 639 km
    ("sin", "syd"): 2, #6  # 6 302 km
    ("syd", "lax"): 4, #12  # 12 066 km
    ("mrs", "sjo"): 3, #9  # 9 203 km
    ("mrs", "lax"): 3, #9  # 9 682 km
    ("lax", "sjo"): 3  #10  # 9 800 km
}

##########
# OVH AS #
##########
Singapore = {
    "sin_r1": {
        "meds": [{"equinix": 0}, {"ntt": 2}, {"vodafone": 5}],
        "interfaces": {
            2: "mrs_r1",
            3: "sin_r2",
            4: "sin_r4",
            5: "syd_r1",
            6: "vodafone",
            7: "ntt",
            8: "equinix"
        }
    },
    
    "sin_r2": {
        "meds": [{"vodafone": 0}, {"telstra": 5}],
        "interfaces": {
            2: "mrs_r1",
            3: "sjo_r1",
            4: "syd_r2",
            5: "sin_r3",
            6: "telstra",
            7: "vodafone",
            8: "sin_r1"
        }
    },
    
    "sin_r3": {
        "meds": None,
        "interfaces": {
            2: "sin_r2",
            3: "sin_r4"
        }
    },
    
    "sin_r4": {
        "meds": None,
        "interfaces": {
            2: "sin_r1",
            3: "sin_r3",
            4: "syd_r4"
        }
    },
}

Sydney = {
    "syd_r1": {
        "meds": [{"telstra": 0}],
        "interfaces": {
            2: "sin_r1",
            3: "syd_r2",
            4: "syd_r4",
            5: "telstra"
        }
    },
    
    "syd_r2": {
        "meds": [{"telstra": 0}, {"ntt": 0}, {"equinix": 4}],
        "interfaces": {
            2: "sin_r2",
            3: "lax_r1",
            4: "syd_r3",
            5: "syd_r1",
            6: "telstra",
            7: "ntt",
            8: "equinix"
        }
    },
    
    "syd_r3": {
        "meds": None,
        "interfaces": {
            2: "syd_r2",
            3: "syd_r4"
        }
    },
    
    "syd_r4": {
        "meds": None,
        "interfaces": {
            2: "sin_r4",
            3: "syd_r3",
            4: "syd_r1"
        }
    }
}

Marseille = {
    "mrs_r1": {
        "meds": None,
        "interfaces": {
            2: "france-IX",
            3: "sjo_r1",
            4: "lax_r1",
            5: "sin_r2",
            6: "sin_r1",
        }
    }
}

San_Jose = {
    "sjo_r1": {
        "meds": [{"softbank": 0}, {"equinix": 1}],
        "interfaces": {
            2: "mrs_r1",
            3: "level3",
            4: "softbank",
            5: "lax_r1",
            6: "equinix",
            7: "sin_r2"
        }
    }
}

Los_Angeles = {
    "lax_r1": {
        "meds": [{"softbank": 2}],
        "interfaces": {
            2: "sjo_r1",
            3: "softbank",
            4: "syd_r2",
            5: "mrs_r1"
        }
    }
}

OVH = {
    "sin": Singapore,
    "syd": Sydney,
    "mrs": Marseille,
    "sjo": San_Jose,
    "lax": Los_Angeles
}

############
# Peers AS #
############
Equinix = {
    "interfaces": {
        2: "sjo_r1",
        3: "sin_r1",
        4: "syd_r2"
    }
}

Vodafone = {
    "interfaces": {
        2: "sin_r2",
        3: "sin_r1"
    }
}

NTT = {
    "interfaces": {
        2: "sin_r1",
        3: "syd_r2"
    }
}

Telstra = {
    "interfaces": {
        2: "sin_r2",
        3: "syd_r2",
        4: "syd_r1",
    }
}

France_IX = {
    "interfaces": {
        2: "mrs_r1"
    }
}

Level3 = {
    "interfaces": {
        2: "sjo_r1"
    }
}

Softbank = {
    "interfaces": {
        2: "sjo_r1",
        3: "lax_r1"
    }
}

PEERS = {
    "equinix": Equinix,
    "vodafone": Vodafone,
    "ntt": NTT,
    "telstra": Telstra,
    "france-IX": France_IX,
    "level3": Level3,
    "softbank": Softbank
}

################
# BGP sessions #
################
# router_name: [LIST OF PEERS]
RR = {
    "sin_r1": {
        "peers": ["sin_r3", "sin_r4", "mrs_r1", "sjo_r1"]
    },
    "sin_r2": {
        "peers": ["sin_r3", "sin_r4", "mrs_r1", "sjo_r1", "lax_r1"]
    },
    "syd_r1": {
        "peers": ["syd_r3", "syd_r4"]
    },
    "syd_r2": {
        "peers": ["syd_r3", "syd_r4", "sjo_r1", "lax_r1"]
    }
}
