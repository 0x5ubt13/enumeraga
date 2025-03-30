# Use a Debian base image
FROM debian:stable-slim
LABEL authors="0x5ubt13"

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    bash \
    gnupg2 \
    curl \
    wget \
    ca-certificates \
    apt-transport-https \
    lsb-release \
    gpg \
    apt-utils \
    sudo \
    procps \
    software-properties-common

RUN curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    apt-get update && apt-get install -y \
        python3 \
        python3-pip \
        pipx \
        git \
        google-cloud-cli \
        build-essential && \
    rm -rf /var/lib/apt/lists/* && \
    # Kinda defeating the best practices above, we need sudo later on
	echo 'subtle ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers && \
	# Create a non-privileged user that the app will run under.
	# See https://docs.docker.com/go/dockerfile-user-best-practices/
	adduser \
    	--disabled-password \
    	--gecos "" \
    	--home "/home/subtle" \
    	--shell "/bin/bash" \
    	--uid 10001 \
    	subtle

# Changing into a non-root user to comply with homebrew
USER subtle
ENV PATH=/home/subtle/.local/bin:/home/subtle/.linuxbrew/bin:/home/subtle/.linuxbrew/sbin:/home/subtle/.local/bin:$PATH

# Create all needed directories for the tools
RUN git clone https://github.com/Homebrew/brew ~/.linuxbrew/Homebrew && \
    mkdir ~/.linuxbrew/bin && \
	ln -s ../Homebrew/bin/brew ~/.linuxbrew/bin && \
	eval $(~/.linuxbrew/bin/brew shellenv) && \
	# Install needed cloud tools 
	brew install \
        cloudfox \
		az \
        awscli \
        oci-cli

# Install Python packages via pipx
RUN pipx install prowler && pipx install scoutsuite

# Install the latest version of Enumeraga
WORKDIR /app

# Copy user configuration to root
USER root
RUN cp -r /home/subtle/.local /root/

# Entrypoint script to handle arguments and output extraction
COPY entrypoint.sh /app/entrypoint.sh
COPY latest /app/enumeraga
RUN chmod +x /app/entrypoint.sh /app/enumeraga

# Define the entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]