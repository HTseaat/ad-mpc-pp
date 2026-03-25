# ---------- 阶段 1：基础环境 ----------
    FROM ubuntu:20.04 AS base

    ENV DEBIAN_FRONTEND=noninteractive \
        TZ=Etc/UTC \
        # PATH=/root/.cargo/bin:$PATH   
        PATH=/usr/local/go/bin:/root/.cargo/bin:$PATH
    
    # 安装系统依赖
    RUN apt-get update && apt-get install -y --no-install-recommends \
            make bison flex libgmp-dev libmpc-dev libntl-dev libflint-dev libffi-dev \
            python3 python3-dev python3-pip python3-gmpy2 libssl-dev wget git build-essential \
            curl tmux ca-certificates \
        && rm -rf /var/lib/apt/lists/*
    
    # 安装 Python 全局依赖
    RUN pip3 install --no-cache-dir \
            cffi Cython==0.29.36 pycryptodome pyzmq pyyaml psutil \
            reedsolo numpy pytest pyparsing hypothesis
    
    WORKDIR /opt/dumbo-mpc
    
    # 拷贝项目源码
    COPY . /opt/dumbo-mpc
    
    # 安装 zfec
    RUN chmod +x install_zfec.sh \
        && ./install_zfec.sh
    
    # 安装 Rust + nightly toolchain
    RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly \
        && /bin/bash -lc "rustup --version"

    # 安装 Go 1.20.8 (arm64)
    RUN wget -q https://go.dev/dl/go1.20.8.linux-arm64.tar.gz \
    && rm -rf /usr/local/go \
    && tar -C /usr/local -xzf go1.20.8.linux-arm64.tar.gz \
    && rm -f go1.20.8.linux-arm64.tar.gz

    
    # ---------- 阶段 2：PBC & Charm-Crypto ----------
    FROM base AS crypto
    
    WORKDIR /opt/dumbo-mpc
    
    # 安装 PBC 库
    RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz \
        && tar -xzf pbc-0.5.14.tar.gz \
        && cd pbc-0.5.14 \
        && ./configure \
        && make \
        && make install \
        && ldconfig \
        && cd .. \
        && rm -rf pbc-0.5.14*
    
    # 安装 Charm-Crypto
    RUN git clone https://github.com/JHUISI/charm.git /tmp/charm \
        && cd /tmp/charm \
        && ./configure.sh \
        && make install \
        # && make test \
        && cd /opt/dumbo-mpc \
        && rm -rf /tmp/charm
    
    # ---------- 阶段 3：编译项目 & 安装 pairing 模块 ----------
    FROM crypto AS build
    
    WORKDIR /opt/dumbo-mpc
    
    # 安装 pairing Python 包
    RUN cd dumbo-mpc/OptRanTriGen/pairing \
        && pip3 install --upgrade setuptools setuptools_rust \
        && pip3 install . \
        # && cd ..
        && cd /opt/dumbo-mpc
    
    # 修补 Flint 头文件路径并安装剩余 Python 包
    RUN cd dumbo-mpc/OptRanTriGen \
        && sed -i '30c #include "flint/flint.h"' /usr/include/flint/flintxx/flint_classes.h \
        && pip3 install . \
        && ln -sf /usr/bin/python3 /usr/bin/python \
        && python3 setup.py build_ext --inplace \
        && cd /opt/dumbo-mpc
    
    # 编译 hbmpc 扩展
    RUN cd hbMPC \
        && python3 setup.py build_ext --inplace \
        && cd /opt/dumbo-mpc
    
    # ---------- 阶段 4：运行镜像 ----------
    FROM ubuntu:20.04 AS runtime
    
    ENV DEBIAN_FRONTEND=noninteractive \
        TZ=Etc/UTC \
        # PATH=/root/.cargo/bin:$PATH
        PATH=/usr/local/go/bin:/root/.cargo/bin:$PATH

    
    ENV CGO_ENABLED=1
    
    # 复制已安装好的环境
    COPY --from=build /opt/dumbo-mpc /opt/dumbo-mpc
    COPY --from=build /root/.cargo /root/.cargo
    COPY --from=build /usr/local/lib /usr/local/lib
    COPY --from=build /usr/local/go /usr/local/go
    
    # 安装少量运行时依赖
    RUN apt-get update && apt-get install -y --no-install-recommends \
    wget git python3 python3-pip \
    gcc g++ make libc6-dev \
    libgomp1 python3-gmpy2 libgmp-dev \
    libgmp10 libntl-dev libflint-dev \
        && rm -rf /var/lib/apt/lists/*

    RUN ln -sf /usr/bin/python3 /usr/bin/python
    
    
    WORKDIR /opt/dumbo-mpc
    
    # 默认命令启动 Bash，用户可自行执行脚本
    ENTRYPOINT [ "/bin/bash" ]