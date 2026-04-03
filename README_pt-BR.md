# BinaryLens

<p align="right">
  <a href="./README.md">
    <img src="https://img.shields.io/badge/lang-English-1f6feb?style=flat-square" alt="English">
  </a>
  <a href="./README_pt-BR.md">
    <img src="https://img.shields.io/badge/lang-Português--BR-009c3b?style=flat-square" alt="Português (BR)">
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/language-C%2B%2B-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white" alt="C++">
  <img src="https://img.shields.io/badge/ui-Qt%206-41CD52?style=for-the-badge&logo=qt&logoColor=white" alt="Qt 6">
  <img src="https://img.shields.io/badge/build-CMake-064F8C?style=for-the-badge&logo=cmake&logoColor=white" alt="CMake">
  <img src="https://img.shields.io/badge/asm-MASM-6B7280?style=for-the-badge" alt="MASM">
  <img src="https://img.shields.io/badge/status-active%20development-111827?style=for-the-badge" alt="Active development">
</p>


BinaryLens é uma ferramenta desktop para Windows voltada à triagem de **arquivos, URLs e IPs** suspeitos.

Ela foi feita em **C++**, usa uma **interface desktop com Qt** e inclui **pattern scanning assistido por assembly** para partes de matching em nível mais baixo. A ideia é destacar sinais úteis rapidamente e facilitar a investigação posterior.

O BinaryLens não foi feito para substituir sandbox, EDR ou reverse engineering manual completo. Ele é uma ferramenta de primeira triagem, e também um projeto prático para quem quer estudar como esse tipo de ferramenta desktop de segurança pode ser construída.

## Site do Projeto

<p align="center">
  <a href="https://binarylens.pages.dev/">
    <img src="https://img.shields.io/badge/SITE%20DO%20PROJETO-ABRIR-7c3aed?style=for-the-badge" alt="Project Website">
  </a>
</p>

## Download

**Release atual:** `v1.2.0`

Se você só quer usar o app, vá até a página de Releases e escolha o pacote que faz mais sentido para o seu uso:

- **Installer** → recomendado para a maioria dos usuários
- **Portable** → versão para extrair e executar

Arquivos da release:

- `BinaryLens-Setup.exe`
- `BinaryLens-Portable-v1.2.0.zip`

As releases empacotadas já incluem o executável e os arquivos de runtime do Qt necessários para rodar o BinaryLens. Não é preciso instalar Qt separadamente.

### Tipos de release

#### Installer
Melhor opção para usuário final comum.

- instalar e executar
- sem configuração manual de Qt
- pensado para funcionar logo após a instalação

#### Portable
Melhor opção se você quer um pacote de extrair e usar.

- extraia o `.zip`
- abra a pasta
- execute `BinaryLensQt.exe`

Também não é necessário instalar Qt separadamente aqui.
<br>
<br>
<p align="center">
  <a href="https://github.com/MrcVnz/BinaryLens/releases/download/v1.2.0/BinaryLens-Portable-v1.2.0.zip">
    <img src="https://img.shields.io/badge/PORTABLE%20VERSION-Download-1f6feb?style=for-the-badge&logo=github" alt="Portable Version">
  </a>
  <a href="https://github.com/MrcVnz/BinaryLens/releases/download/v1.2.0/BinaryLens-Setup.exe">
    <img src="https://img.shields.io/badge/INSTALLER%20VERSION-Download-2ea043?style=for-the-badge&logo=windows" alt="Installer Version">
  </a>
</p>

---

## Demo

Visão rápida do fluxo atual da interface desktop:

<p align="center">
<img src="assets/demo.gif" width="856" alt="Demonstração do BinaryLens">
</p>

---

## Para quem é este projeto

O BinaryLens é voltado principalmente para:

- estudantes de cibersegurança
- iniciantes em reverse engineering
- pessoas estudando malware triage
- desenvolvedores interessados em ferramentas nativas de segurança para Windows
- pessoas que querem estudar um projeto prático em **C++ + Qt + MASM**

Este projeto faz mais sentido para quem já conhece o básico de programação e quer avançar para ferramentas de segurança focadas em Windows.

## O que ele faz

- analisa arquivos locais, URLs e alvos em IP bruto a partir de uma interface desktop
- combina múltiplos sinais de análise em um único relatório
- suporta tanto **triagem de arquivos** quanto **triagem contextual de URL / IP**
- usa verificações como:
  - geração de hash
  - parsing de PE
  - inspeção de imports
  - inspeção de arquivos compactados
  - verificação de payloads embutidos
  - calibração contextual de payload embutido e confiabilidade do sinal
  - tratamento mais cuidadoso para arquivos compactados, evitando superescalar motifs low-level em containers limpos
  - indicadores de abuso em scripts
  - matching com YARA
  - consultas ao VirusTotal para arquivos, URLs e reputação de IP quando aplicável
- inclui pattern scanning com suporte de assembly para partes sensíveis a desempenho
- oferece exportação de relatórios, exportação de IOCs, cópia para a área de transferência e visualização orientada para analistas

## Casos de uso típicos

Você pode usar o BinaryLens para:

- inspecionar um arquivo suspeito antes de uma análise mais profunda
- ter uma visão inicial rápida de uma URL ou IP
- puxar contexto de provider / ASN / ownership para alvos em IP bruto
- exportar relatórios e IOCs para trabalho posterior
- estudar como uma ferramenta nativa de triagem para Windows é estruturada internamente

## Estrutura do projeto

```text
BinaryLens/
├─ BinaryLens/
│  ├─ asm/
│  ├─ config/
│  ├─ include/
│  ├─ plugins/
│  ├─ rules/
│  └─ src/
│     ├─ analyzers/
│     ├─ asm/
│     ├─ core/
│     ├─ scanners/
│     └─ services/
├─ qt_app/
│  ├─ include/
│  ├─ resources/
│  └─ src/
├─ assets/
├─ release_support/
├─ CMakeLists.txt
└─ .gitignore
```

## Requisitos

- Windows 10 ou 11
- Visual Studio 2022 ou mais recente com ferramentas de desktop C++
- CMake 3.21+
- Qt 6 (este projeto foi montado em torno do **Qt 6.10.2 msvc2022_64**)
- MASM / ml64 (instalado com o Visual Studio)
- Inno Setup 6 (somente se você quiser gerar o installer por conta própria)

## Clonando o repositório

Usando Git:

```bash
git clone https://github.com/MrcVnz/BinaryLens.git
cd BinaryLens
```

Ou baixe o projeto como ZIP diretamente do GitHub e extraia localmente.

## Compilando

Abra a raiz do projeto no Visual Studio como um **projeto CMake**.

Se o Qt não estiver instalado no caminho padrão usado por este repositório, defina `CMAKE_PREFIX_PATH` apontando para sua instalação do Qt antes de configurar.

Caminho padrão esperado:

```text
C:/Qt/6.10.2/msvc2022_64
```

### Passos de build

1. Abra a pasta raiz no Visual Studio
2. Deixe o CMake configurar o projeto
3. Compile o target `BinaryLensQt`
4. Execute o binário gerado

O projeto pode ser configurado para chamar o `windeployqt` após o build, para que o runtime do Qt seja copiado automaticamente ao lado do executável.

## Fluxo de release

O repositório agora inclui arquivos de suporte para gerar os dois formatos de release para Windows:

- **portable release**
- **installer release**

Arquivos úteis:

- `release_support/make_portable_release.bat`
- `release_support/BinaryLens.iss`

Fluxo típico:

1. compilar `x64-Release`
2. rodar `release_support/make_portable_release.bat`
3. testar a pasta gerada `BinaryLens-Portable`
4. compactar para a release portable
5. abrir `release_support/BinaryLens.iss` no Inno Setup e compilar o installer

## Configuração do VirusTotal

Existem duas formas suportadas de usar a integração com o VirusTotal:

### 1. Release pronta / executável empacotado

Para releases públicas empacotadas, o app é distribuído de forma que o usuário final não precise configurar manualmente os arquivos do Qt.

Para builds a partir do código-fonte, o VirusTotal continua seguindo a configuração local do projeto.

### 2. Compilando a partir do código-fonte

Se você clonar o repositório e compilar o BinaryLens por conta própria, crie este arquivo localmente:

```text
BinaryLens/config/config.json
```

Você pode copiar o arquivo de exemplo abaixo e preencher com sua própria chave:

```text
BinaryLens/config/config.example.json
```

Formato esperado:

```json
{
  "virustotal_api_key": "COLE_SUA_CHAVE_DO_VIRUSTOTAL_AQUI"
}
```

## Observações

- O ponto de entrada atual do app desktop é o frontend em **Qt**.
- O repositório não deve incluir saída de build, DLLs do Qt já deployadas ou segredos de runtime pessoais.
- O BinaryLens deve ser tratado como uma ferramenta de triagem e aprendizado, não como autoridade final para dizer se algo é malicioso.
- A análise de IP bruto foi pensada para fornecer contexto e apoio à triagem, não inteligência completa de internet.
- Os binários de release podem ser empacotados para usuário final, mas builds a partir do código-fonte continuam sendo o melhor caminho para quem quer inspecionar ou modificar o projeto.

## Por que o repositório é estruturado assim

Este projeto cresceu em etapas. O código principal de análise, a parte em assembly e a interface Qt ficam em áreas separadas de propósito, para manter a base mais fácil de entender.

- `BinaryLens/src/core` contém o fluxo de análise e a lógica de veredito
- `BinaryLens/src/analyzers` contém os módulos de análise específicos por feature
- `BinaryLens/src/services` cobre helpers externos, como uso de APIs
- `BinaryLens/src/asm` e `BinaryLens/asm` contêm a ponte entre C++ / MASM e as rotinas de baixo nível
- `qt_app` contém a interface desktop atual
- `release_support` contém os arquivos auxiliares para empacotamento das releases

## Estado atual

BinaryLens é um projeto pessoal em evolução. Espere bugs, falta de features e mudanças rápidas.

Se você clonar, trate como um repositório real de desenvolvimento, não como um produto comercial finalizado.

## Criador

GitHub: **MrcVnz**