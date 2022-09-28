# Trabalho realizado na semana 3

# Caracterização e exploração de vulnerabilidade
## CVE-2014-6271 (ShellShock)


## Identificação:

   - **ShellShock** é um exploit que consiste em correr código remoto em máquinas UNIX (principalmente)
   - Falha de segurança presente em máquinas que correm *bash* das versões 1.14 até 4.3
   - Utilizando código simples como `env x='() { :;}; echo VULNERABLE; exit;’ bash -c ‘echo NOT VULNERABLE’` conseguimos ter *root* da máquina

## Catalogação:

- Descoberta por [Stéphane Chazelas](https://unix.stackexchange.com/users/22565/st%c3%a9phane-chazelas) e comunicada ao mantenedor da Bash a 12 de setembro de 2014
- Divulgada publicamente a 24 de setembro de 2014
- Categorizada com gravidade de 10 na escala de NIST
- Não existe *bug bounty* associada


## Exploit:

   - Esta vulnerabilidade explora o facto de o *bash* conseguir executar novas instâncias de si mesmo, assim como o facto de executar *trailing strings* ao definir variáveis de ambiente
   - Vulnerabilidade do tipo RCE (Remote Code Execution)


## Ataques:
   - Ainda hoje são identificados ataques *ShellShock*
   - O atacante consegue obter *root* da máquina, sendo que pode fazer/executar o que quiser dentro do servidor remotamente

