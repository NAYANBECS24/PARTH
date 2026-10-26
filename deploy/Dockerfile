FROM python:3.12-slim-bookworm

ARG JADX_VERSION=1.5.3
ARG ANDROID_COMMANDLINE_TOOLS=15859902
ARG ANDROID_BUILD_TOOLS=35.0.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    ANDROID_HOME=/opt/android-sdk \
    SHADOWPATH_DATA_DIR=/app/data \
    SHADOWPATH_DATABASE_URL=/app/data/shadowpath.db

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools" /opt/jadx \
    && curl -fsSL "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_COMMANDLINE_TOOLS}_latest.zip" -o /tmp/android-tools.zip \
    && unzip -q /tmp/android-tools.zip -d /tmp/android-tools \
    && mv /tmp/android-tools/cmdline-tools "$ANDROID_SDK_ROOT/cmdline-tools/latest" \
    && yes | "$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" --licenses > /dev/null \
    && "$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" "platform-tools" "build-tools;${ANDROID_BUILD_TOOLS}" \
    && rm -rf /tmp/android-tools /tmp/android-tools.zip

RUN curl -fsSL "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -o /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && JADXBIN="$(find /opt/jadx -type f -path '*/bin/jadx' -print -quit)" \
    && test -n "$JADXBIN" \
    && ln -s "$JADXBIN" /usr/local/bin/jadx \
    && ln -s "$ANDROID_SDK_ROOT/build-tools/${ANDROID_BUILD_TOOLS}/aapt2" /usr/local/bin/aapt2 \
    && ln -s "$ANDROID_SDK_ROOT/build-tools/${ANDROID_BUILD_TOOLS}/aapt" /usr/local/bin/aapt \
    && ln -s "$ANDROID_SDK_ROOT/build-tools/${ANDROID_BUILD_TOOLS}/apksigner" /usr/local/bin/apksigner \
    && ln -s "$ANDROID_SDK_ROOT/platform-tools/adb" /usr/local/bin/adb \
    && rm -f /tmp/jadx.zip

WORKDIR /app
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt
COPY api ./api
COPY backend ./backend
COPY scripts ./scripts
COPY fixtures ./fixtures
COPY data ./data
RUN python -c "from backend.database import initialise_database; initialise_database()"

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "backend.api:app", "--host", "0.0.0.0", "--port", "8000"]
