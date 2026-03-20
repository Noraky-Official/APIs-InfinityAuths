#pragma once
#include <string>
#include "api.hpp"
#include "skCrypt.hpp"

// Credenciais da Aplicação
static std::string name = "SuaApp"; 
static std::string ownerid = "SeuOwnerID";
static std::string secret = "SeuSecret"; // Novo em V3
static std::string version = "1.0";

// Instância Global para uso em todo o projeto
static InfinityAuthV2::API auth(name, ownerid, secret, version);
