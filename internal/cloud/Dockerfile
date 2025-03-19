# Use a Debian base image
FROM continuumio/miniconda3
LABEL authors="0x5ubt13"

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    bash \
    curl \
    wget \
    gnupg \
    software-properties-common \
    python3 \
    python3-pip \
    git \
    sudo \
    build-essential \
    && rm -rf /var/lib/apt/lists/* && \
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

# Install pipx
RUN pip install --upgrade pip && \
    pip install --user pipx --break-system-packages

# Create all needed directories for the tools
RUN git clone https://github.com/Homebrew/brew ~/.linuxbrew/Homebrew && \
    mkdir ~/.linuxbrew/bin && \
	ln -s ../Homebrew/bin/brew ~/.linuxbrew/bin && \
	eval $(~/.linuxbrew/bin/brew shellenv) && \
	brew --version && \
	mkdir ~/.kube/ && \
	# Install needed cloud tools 
	brew install \
        cloudfox \
		az \
        awscli

# Verify installations
RUN curl --version && \
    brew --version && \
    python3 --version && \
    pipx --version && \
    brew --version && \
    git --version && \
    conda --version

# Install Python packages via pipx
RUN pipx install scoutsuite prowler

# Use conda for pmapper
RUN conda create -n pmapper -y && \
    conda init bash && \
    /bin/bash -c "source /opt/conda/etc/profile.d/conda.sh && conda activate pmapper && pip install principalmapper"

WORKDIR /app

# Copy user configuration to root
USER root
RUN cp -r /home/subtle/.conda /root/ && \
    cp -r /home/subtle/.local /root/

USER subtle

# Entrypoint script to handle arguments and output extraction
COPY --chown=subtle:subtle entrypoint.sh /app/entrypoint.sh
COPY --chown=subtle:subtle latest /app/enumeraga
RUN chmod +x /app/entrypoint.sh /app/enumeraga

# Define the entrypoint
ENTRYPOINT ["sudo", "-E", "/app/entrypoint.sh"]