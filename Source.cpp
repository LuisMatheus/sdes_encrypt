#include <string>
#include <bitset>
#include <iostream>

#include"SDES.h"
#include"sdesData.h"

using namespace std;
int main() {
    SDES s;
    sdesData* d = s.encrypt("As origens do DES remontam ao in�cio da d�cada de 1970. Em 1972, ap�s concluir um estudo sobre as necessidades de seguran�a de informa��o do governo norte-americano, o ent�o NBS (National Bureau of Standards), atualmente conhecido como NIST (National Institute of Standards and Technology), na �poca o �rg�o de padr�es do governo norte-americano) identificou a necessidade de um padr�o governamental para criptografia de informa��es n�o confidenciais, por�m sens�veis. Em conseq��ncia, em 15 de Maio de 1973, ap�s uma consulta � NSA, o NBS solicitou proposta para um algoritmo de criptografia que atendesse a crit�rios rigorosos de projeto. Entretanto, nenhuma das propostas recebidas se mostrou vi�vel. Uma segunda solicita��o foi aberta em 27 de Agosto de 1974. Desta vez, a IBM submeteu uma proposta candidata que foi considerada aceit�vel: um algoritmo de criptografia desenvolvido no per�odo de 1973-1974 baseado num algoritmo mais antigo, o algoritmo L�cifer de Horst Feistel. A equipe da IBM envolvida no projeto do algoritmo inclu�a Feistel, Walter Tuchman, Don Coppersmith, Alan Konheim, Carl Meyer, Mike Matyas, Roy Adler, Edna Grossman, Bill Notz, Lynn Smith and Bryant Tuckerman. Preocupa��es sobre a seguran�a e a opera��o relativamente lenta do DES motivou pesquisadores a propor uma variedade de alternativas para a cifragem em bloco, que come�aram a aparecer no final dos anos 1980 e in�cio dos anos 1990. Alguns exemplos podem ser citados, como: RC5, Blowfish, NewDES, SAFER, CAST5 and FEAL. A maioria deles mant�m o tamanho de bloco de 64 bits do DES, e portanto funcionam como substitui��o ao DES se necess�rio, embora usem tipicamente uma chave de 64 ou 128 bits. Na URSS o algoritmo GOST 28147-89 foi introduzido, com um bloco de 64 bits e chave de 256 bits, que mais tarde foi utilizada na R�ssia. At� mesmo o pr�prio DES pode ser adaptado para ser usado de modo mais seguro.Muitos ex - usu�rios de DES agora utilizam o 3DES(tamb�m conhecido como TDES) que foi descrito e analisado por um dos patenteadores do DES; este algoritmo envolve aplicar o DES tr�s vezes com duas(2TDES) ou tr�s(3TDES) chaves diferentes.TDES � considerada adequadamente segura, embora seja bastante lenta.Uma alternativa menos custosa computacionalmente falando � a DES - X, que aumenta o tamanho da chave fazendo um XOR antes e depois do DES.GDES � uma variante do DES proposta de forma a aumentar a velocidade da criptografia, mas mostrou - se suscet�vel � criptoan�lise diferencial.Em 2001, ap�s uma competi��o internacional, NIST selecionou um novo algoritmo, o AES(Advanced Encryption Standard), como substituto ao DES.O algoritmo que foi selecionado como o AES foi enviado por seus criadores sob o nome Rijndael.Outros finalistas na competi��o do NIST incluem RC6, Serpent, MARS e Twofish.");
    cout << s.decrypt(d);
}
