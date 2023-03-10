# Trabalho realizado na semana 3

# Caracterização e exploração de vulnerabilidade
> CVE-2014-6271 (ShellShock)

## Identificação

   - **ShellShock** é um exploit que consiste em correr código remoto em máquinas UNIX (principalmente)
   - Falha de segurança presente em máquinas que correm *bash* das versões 1.14 até 4.3
   - Utilizando código simples como `env x='() { :;}; echo VULNERABLE; exit;' bash -c 'echo NOT VULNERABLE'` conseguimos ter *root* da máquina

## Catalogação

- Descoberta por [Stéphane Chazelas](https://unix.stackexchange.com/users/22565/st%c3%a9phane-chazelas) e comunicada ao mantenedor da *bash* a 12 de setembro de 2014
- Divulgada publicamente a 24 de setembro de 2014
- Categorizada com gravidade de 10 na escala de NIST
- Não existe *bug bounty* associada

## Exploit

   - Esta vulnerabilidade explora o facto de a *bash* conseguir executar novas instâncias de si mesma, assim como o facto de executar *trailing strings* ao definir variáveis de ambiente
   - Vulnerabilidade do tipo RCE (Remote Code Execution)


## Ataques
   - Ainda hoje são identificados ataques *ShellShock*
   - Em vários casos, o atacante consegue obter *root* da máquina, sendo que pode fazer/executar o que quiser dentro do servidor remotamente

### Replicar ataques

Para executar uma *bash* vulnerável a este exploit, podemos executar, numa máquina com Docker instalado, o seguinte comando:

```bash  
ID="$(docker run -d rohitnss/shellshock)" && echo $ID && docker exec -it $ID /bin/bash && docker rm -f $ID > /dev/null
```

O comando irá criar um container com a versão da *bash* vulnerável e executar a *bash* dentro do container.

Por fim, podemos executar o script de verificação para a vulnerabilidade *ShellShock*:

```bash
env x='() { :;}; echo VULNERABLE; exit;' bash -c "echo 'NOT VULNERABLE'"
```

Para sair do container, basta executar o comando `exit` na *bash* do container. O container será automaticamente removido.

> Podem ser encontrados exemplos de automações para este exploit no [Metasploit](https://null-byte.wonderhowto.com/how-to/exploit-shellshock-web-server-using-metasploit-0186084/) e na [ExploitDB](https://www.exploit-db.com/exploits/34900).

---

# CTF - Sanity Check

Após lermos a descrição desta challenge, percebemos imediatamente que a flag da challenge estaria no endpoint [/rules](https://www.ctf-fsi.fe.up.pt/rules).

Tendo isto em conta, para resolver a challenge, o nosso procedimento foi:

## Step 1 - Aceder à secção rules

<figure width="50%">
   <img src="images/logbook3/rules.png" alt="Página de regras com a flag destacada" width="50%" />
   <figcaption><strong>Fig 1.</strong> Flag no endpoint /rules</figcaption>
</figure>

Ao aceder a este endpoint e ler as regras, percebemos que a flag se encontra em *cleartext*, numa das regras.

## Step 2 - Submeter a flag

<figure width="50%">
   <img src="images/logbook3/submit.png" alt="Ecrã de submissão da flag para a challenge &quot;Sanity Check&quot; com a flag preenchida com o valor obtido no passo anterior" width="50%" />
   <figcaption><strong>Fig 2.</strong> Submeter a flag</figcaption>
</figure>

Após submeter a flag, a challenge de Sanity Check encontra-se resolvida.
