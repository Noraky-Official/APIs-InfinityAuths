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
// IMPORTANTE: Declare "InfinityAuthApp InfinityApp;" no seu main.cpp ou arquivo principal.
extern InfinityAuthApp InfinityApp;
