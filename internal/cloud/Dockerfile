# Use a Debian base image
FROM continuumio/miniconda3
LABEL authors="0x5ubt13"

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    gnupg \
    software-properties-common \
    python3 \
    python3-pip \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install pipx
RUN python3 -m pip install --user pipx && \
    python3 -m pipx ensurepath

# Add pipx to PATH
ENV PATH="/root/.local/bin:${PATH}"

# Install Homebrew (Linuxbrew)
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" && \
    eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"

# Verify installations
RUN curl --version && \
    python3 --version && \
    pipx --version && \
    brew --version && \
    git --version && \
    conda --version

# Install Python packages via pipx
RUN pipx install scoutsuite prowler

# Install Homebrew packages
RUN brew install cloudfox

RUN conda create -n pmapper && \
    /bin/bash -c "source activate pmapper && pip install principalmapper"

# Set your working directory
WORKDIR /app

# Entrypoint script to handle arguments and output extraction
COPY entrypoint.sh /app/entrypoint.sh
COPY "../../releases/latest" /app/enumeraga
RUN chmod +x /app/entrypoint.sh /app/enumeraga

# Define the entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]