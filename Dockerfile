# The safetwin command in a container. Mount the folder with the policy and the data at /work, and pass the
# key in an environment variable (a key file mounted from the host belongs to another user inside, which
# safetwin refuses):
#
#   docker run --rm -v "$PWD:/work" -e SAFETWIN_KEY safetwin mask masking.yaml
#
# The image runs as an unprivileged user. Build it with:  docker build -t safetwin .

FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip wheel --no-cache-dir --no-deps --wheel-dir /dist .

FROM python:3.12-slim
COPY --from=build /dist/ /tmp/dist/
RUN python -m pip install --no-cache-dir /tmp/dist/*.whl \
    && rm -rf /tmp/dist \
    && useradd --create-home --uid 10001 safetwin
USER safetwin
WORKDIR /work
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["safetwin"]
CMD ["--help"]
