# FSI - L02G06

## CVE-2014-6271 (ShellShock)

### Identificação: descrição geral da vulnerabilidade, incluindo aplicações/sistemas operativos relevantes (max 4 itens com 20 palavras cada)


# Identificação:

   - **ShellShock** é um exploit que consiste em correr código remoto em máquinas UNIX (principalmente)
   - Falha de segurança presente em máquinas que correm *bash* das versões 1.14 até 4.3
   - Utilizando código simples como `env x='() { :;}; echo VULNERABLE; exit;’ bash -c ‘echo NOT VULNERABLE’` conseguimos ter *root* da máquina

# Catalogação:

- Descoberta por [Stéphane Chazelas](https://unix.stackexchange.com/users/22565/st%c3%a9phane-chazelas) e comunicada ao mantenedor da Bash a 12 de setembro de 2014
- Divulgada publicamente a 24 de setembro de 2014
- Categorizada com gravidade de 10 na escala de NIST
- Não existe *bug bounty* associada


# Exploit:

   - Esta vulnerabilidade explora a execução de código

Esta vulnerabilidade foi descoberta por [Stéphane Chazelas](https://unix.stackexchange.com/users/22565/st%c3%a9phane-chazelas) e, apesar de conhecida, continua a afetar inúmeros servidores e até mesmo computadores pessoais.

Para testarmos se um dispositivo sofre desta vulnerabilidade, podemos correr o seguinte script:

```bash
env x='() { :;}; echo VULNERABLE; exit;' bash -c "echo 'NOT VULNERABLE'"
```

-- INFORMATIVO --
GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock." NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.
------------------

A vulnerabilidade *ShellShock*, descoberta em 2014, constinua a ser relevante em 2022, devido à sua facilidade de utilização
Este bug encontra-se na linha de comandos do Bash e consegue afetar vários sistemas operativos, incluindo Unix-based, Windows e sistemas conectados aos mesmos por uma *network*
Introduzido em 1989

### Catalogação: o que se sabe sobre o seu reporting, quem, quando, como, bug-bounty, nível de gravidade, etc. (max 4 itens com 20 palavras cada)





### Exploit: descrever que tipo de exploit é conhecido e que tipo de automação existe, e.g., no Metasploit (max 4 itens com 20 palavras cada)

Para emular um ambiente vulnerável a este CVE, pode-se utilizar o Dockerfile criado no diretório [ambiente](/ambiente/) seguindo as instruções contidas no README.

...

`ID="$(docker run -d rohitnss/shellshock)" && echo $ID && docker exec -it $ID /bin/bash && docker rm -f $ID > /dev/null`


Podemos automatizar este exploit usando a framework Metasploit da seguinte forma:
