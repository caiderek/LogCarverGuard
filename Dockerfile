# LogCarverGuard: the MCP proxy as a centralized network
# service. Bundles the admin CLI into the same image, since it only ever
# operates on the same SQLite files the server uses
# (docker exec <container> dotnet cli/LogCarverGuard.Cli.dll ...).

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Project files first, so the restore layer is cached across source-only changes.
COPY src/LogCarverGuard.Core/*.csproj src/LogCarverGuard.Core/
COPY src/LogCarverGuard.Tools/*.csproj src/LogCarverGuard.Tools/
COPY src/LogCarverGuard.Hosting/*.csproj src/LogCarverGuard.Hosting/
COPY src/LogCarverGuard.Server/*.csproj src/LogCarverGuard.Server/
COPY src/LogCarverGuard.Cli/*.csproj src/LogCarverGuard.Cli/
RUN dotnet restore src/LogCarverGuard.Server/LogCarverGuard.Server.csproj \
 && dotnet restore src/LogCarverGuard.Cli/LogCarverGuard.Cli.csproj

COPY src/ src/
RUN dotnet publish src/LogCarverGuard.Server/LogCarverGuard.Server.csproj -c Release -o /app/server --no-restore \
 && dotnet publish src/LogCarverGuard.Cli/LogCarverGuard.Cli.csproj -c Release -o /app/cli --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
COPY --from=build /app/server ./server
COPY --from=build /app/cli ./cli

# The audit log and the API-key store are SQLite files under /data; mount a
# volume there so they survive restarts and image upgrades.
RUN mkdir -p /data
ENV LOGCARVERGUARD_AUDIT_DB_PATH=/data/logcarverguard-audit.db
ENV LOGCARVERGUARD_APIKEYS_DB_PATH=/data/logcarverguard-apikeys.db
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

# Non-root user the base image already ships; /data must be owned by it.
# VOLUME comes after the chown: changes made to a volume path after the
# VOLUME instruction are discarded by the legacy builder.
RUN chown -R $APP_UID /data /app
VOLUME ["/data"]
USER $APP_UID

# LOGCARVERGUARD_SQLSERVER_CONNECTION_STRING (or _FILE) is deliberately not
# set here: it is a real credential and must be injected at startup.
ENTRYPOINT ["dotnet", "server/LogCarverGuard.Server.dll"]
