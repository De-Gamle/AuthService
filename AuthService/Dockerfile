# Brug en officiel .NET runtime som base image
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

# Brug en officiel .NET SDK som build image
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Kopier projektfilen og gendan afhængigheder
COPY ["AuthService.csproj", "./"]
RUN dotnet restore "AuthService.csproj"

# Kopier resten af applikationen og byg den
COPY . .
RUN dotnet build -c Release -o /app/build

# Publicer applikationen
FROM build AS publish
RUN dotnet publish -c Release -o /app/publish

# Brug runtime image til at køre applikationen
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "AuthService.dll"]