FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /src
COPY . .
RUN dotnet publish Legacy.Maliev.AuthService.IdentityMigration/Legacy.Maliev.AuthService.IdentityMigration.csproj \
    --configuration Release \
    --output /app/publish \
    --no-self-contained

FROM mcr.microsoft.com/dotnet/runtime:10.0-alpine AS runtime
WORKDIR /app
ENV DOTNET_EnableDiagnostics=0
COPY --from=build /app/publish .
USER $APP_UID
ENTRYPOINT ["dotnet", "Legacy.Maliev.AuthService.IdentityMigration.dll"]
