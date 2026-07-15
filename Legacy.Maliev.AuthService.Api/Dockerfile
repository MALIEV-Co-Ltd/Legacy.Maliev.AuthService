FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /src
RUN apk add --no-cache git \
    && git clone --filter=blob:none --no-checkout https://github.com/MALIEV-Co-Ltd/Maliev.Aspire.git /dependencies/Maliev.Aspire \
    && git -C /dependencies/Maliev.Aspire checkout 085f24b8b6b19c5a8e932b229d93421b03bcd032 \
    && git clone --filter=blob:none --no-checkout https://github.com/MALIEV-Co-Ltd/Maliev.MessagingContracts.git /dependencies/Maliev.MessagingContracts \
    && git -C /dependencies/Maliev.MessagingContracts checkout c533c12a8154f5cf7c4fbc9734e82a62705ac60f
COPY . .
RUN dotnet publish Legacy.Maliev.AuthService.Api/Legacy.Maliev.AuthService.Api.csproj \
    --configuration Release \
    --output /app/publish \
    --no-self-contained \
    -p:UseLocalMalievDependencies=true \
    -p:MalievWorkspaceRoot=/dependencies

FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine AS runtime
WORKDIR /app
ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_EnableDiagnostics=0
COPY --from=build /app/publish .
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "Legacy.Maliev.AuthService.Api.dll"]
