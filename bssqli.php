<?php 

/*
 * Autor: Rafael Augusto. | a.k.a: Brlo0ping.
 * Script em php com a finalidade de buscar e verificar todos os sites vulneráveis a sql injection de um seguinte servidor de hospedagem compartilhada.
 * Um site vulnerável, hospedado em um servidor mal configurado e  mal protegido, irá corromper a segurança de todos os outros sites  e sistemas que estão hospedados no mesmo servidor(Mass Defacer). 
 * A intenção do script é evitar a má escolha de um sv de hospedagem e evitar um futuro mass defacer. 
 */


class BSSqli{
	private $host, $dork;
	private $url_busca;		
	private static $txt_list = "sites.txt";
	private static $prefix = "ip:";
	private static $buscador = "http://www.bing.com/search?q=";


	/* verifica se as variaveis dork e host foram setadas no input */
	public function __construct($host,$dork){				
		if (!empty($host) && !empty($dork)):			
			self::deletaTxt();
			$this->host = $host;
		    $this->dork = $dork; 				    	    	  
		else:
			$this->banner();
		    exit();
		endif;
	}	

	private static function banner(){
		print "\n\t\t[ BSsqli (Bing Scan Sql Injection) ] \n"; 
		print "\t[ Autor: Rafael Augusto | a.k.a: Brlo0ping ] \n";
		print "\t[ Modo de usar: php f2sv.php <ip> <dork ex:php?id=>) ] \n \n";		
	}

	public function setaLink($pagina){	          	  	         
	  	 $this->url_busca = self::$buscador.self::$prefix.$this->host."%20".$this->dork.'&first='.$pagina.'&FORM=PERE';
	}
	

	private static function deletaTxt(){
		if (file_exists(self::$txt_list)):
			unlink(self::$txt_list);
		endif;
	}

	private function grava($str){	
		$fp = fopen(self::$txt_list, "a"); 
		fwrite($fp, $str."\n");
		fclose($fp);
	}

    /* Captura o código fonte do bing com os resultado da busca */
	private function getCodigoFonte($link){
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $link);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);             
		$codigo =  curl_exec($ch);
		curl_close($ch);        

		return $codigo;
	}
    
	private function recortaString($str){		
		$pos = strpos($str, "</cite>");
		$link = substr($str, 0, $pos);
		$link = str_replace("<strong>", "", $link);
		$link = str_replace("</strong>", "", $link);		
		return $link;
	}	

	private function getLinks(){   	    	
	    $url = $this->url_busca;        
		$l = $this->getCodigoFonte($url);
		$l = explode("<cite>", $l);

		for($i = 1; $i <= count($l) -1; $i++):
			$links[$i] = $this->recortaString($l[$i]);		   		    
		endfor;		

		return $links;
	}

    private static function referencias(){
    	 $ref = array(    	 	
    	 	"Warning: mysql_fetch_array():",
    	 	"You have an error in your SQL syntax",
    	 	"MySQL server version",
    	 	"Syntax error converting the nvarchar value",
    	 	"SQL Server error",
    	 	"mysql_fetch_assoc()",    	 	 	 
    	 	"consulta no banco",
    	 	"Erro MySQL",
    	 	"You have an error in your SQL",
    	 	"Warning:",
    	 	"Warning: mysql_num_rows():",
    	 	"mysql_num_rows()"
    	 	);

    	 return $ref;
    }       
   
    private function retornaSiteVul($codigo_fonte,$url_site){    	
    	$ref = self::referencias();    	
    	echo "Verificando: " . $url_site . "\n";        

    	for($i = 1; $i <= count($ref); $i++):    
            if (strripos($codigo_fonte, $ref[$i])):                                  
            	return $url_site;
            endif;
		endfor;	
	    
    }
    
    private function exibeSitesVuls($sites){
    	echo "\n\n\t[ SITES VULNERÁVEIS DO SERVIDOR ".$this->host." ]\n\n";
    	foreach($sites as $links):    		
    		echo "\t".$links."\n";    	   
    	    $this->grava($links);
		endforeach;
    }         
    
    public function iniciaVerificacao(){
       $links = $this->getLinks();
       for($i = 1; $i <= count($links); $i++):       	          	   
           $codigo_fonte = strtoupper($this->getCodigoFonte($links[$i]."'"));   
           $sitesVuls[] = $this->retornaSiteVul($codigo_fonte, $links[$i]);                   
       endfor;        
       $this->exibeSitesVuls($sitesVuls);                          
    }

}

$host = trim($argv[1]);
$dork = trim($argv[2]);

$bssqli = new BSsqli($host,$dork);
$bssqli->setaLink(1);
$bssqli->iniciaVerificacao();

while(1):
	 print "\nDigite C para continuar buscando ou Q para finalizar: ";	 
	 $s = strtoupper(trim(fgets(STDIN)));
	 
	 switch($s):
	    case "C":	  	                        	         
	        $pag = $pag + 10;
	        $bssqli->setaLink($pag);
	        $bssqli->iniciaVerificacao();
	    break;

	    case "Q":
	        exit();
	    break;
	 endswitch;
endwhile;


