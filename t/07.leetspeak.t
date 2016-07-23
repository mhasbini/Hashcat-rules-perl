
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../";
use bignum; # hacky fix for Int types (ie. no '')

require_ok Hashcat::Rules;
my @plains=('\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}eNcb','}Gmi','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4xa',6,639,66,'6DGU',7,796,'7b4Xx',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','cgzh','D','DAHG','dd','dsjny','DYox','E','e','edeof','eP1h0','Epy','esg','FS','FSNxm','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','iGl','ijhFf','Int','J]gLb','J29T','JaGwu','JF','jlfb','JSAQ','jx','KFE','khMO','KQGPY','KVN','kwe','L','l6','LanZD','m','MAZE','miae','MoP','ms','MWL','mZ2','N','ncadn','NCWe9','nr','O','o','oES','Of','oJXM','p','Pa.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','Rx,M','rya','S4h','szKO','ten','tfryk','tjRha','tU','V','VDYe','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#Vo','ZCQ','zgAz','ZGYLU','zt','ZV0K');
my $rulesEngine = Hashcat::Rules->new(verbose => 0);

subtest 'Rule "## rule: leetspeak single"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('## rule: leetspeak single', \@plains)], [] );
};

subtest 'Rule "## limits: none"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('## limits: none', \@plains)], [] );
};

subtest 'Rule "## example: john ---> j0hn"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('## example: john ---> j0hn', \@plains)], [] );
};

subtest 'Rule "## extras: case original, lower, upper"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('## extras: case original, lower, upper', \@plains)], [] );
};

subtest 'Rule ""' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('', \@plains)], [] );
};

subtest 'Rule "sa4"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('sa4', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}eNcb','}Gmi','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4x4',6,639,66,'6DGU',7,796,'7b4Xx',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','cgzh','D','DAHG','dd','dsjny','DYox','E','e','edeof','eP1h0','Epy','esg','FS','FSNxm','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','iGl','ijhFf','Int','J]gLb','J29T','J4Gwu','JF','jlfb','JSAQ','jx','KFE','khMO','KQGPY','KVN','kwe','L','l6','L4nZD','m','MAZE','mi4e','MoP','ms','MWL','mZ2','N','nc4dn','NCWe9','nr','O','o','oES','Of','oJXM','p','P4.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','Rx,M','ry4','S4h','szKO','ten','tfryk','tjRh4','tU','V','VDYe','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#Vo','ZCQ','zgAz','ZGYLU','zt','ZV0K'] );
};

subtest 'Rule "sa@"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('sa@', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}eNcb','}Gmi','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4x@',6,639,66,'6DGU',7,796,'7b4Xx',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','cgzh','D','DAHG','dd','dsjny','DYox','E','e','edeof','eP1h0','Epy','esg','FS','FSNxm','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','iGl','ijhFf','Int','J]gLb','J29T','J@Gwu','JF','jlfb','JSAQ','jx','KFE','khMO','KQGPY','KVN','kwe','L','l6','L@nZD','m','MAZE','mi@e','MoP','ms','MWL','mZ2','N','nc@dn','NCWe9','nr','O','o','oES','Of','oJXM','p','P@.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','Rx,M','ry@','S4h','szKO','ten','tfryk','tjRh@','tU','V','VDYe','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#Vo','ZCQ','zgAz','ZGYLU','zt','ZV0K'] );
};

subtest 'Rule "sb6"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('sb6', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}eNc6','}Gmi','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4xa',6,639,66,'6DGU',7,796,'764Xx',81,84,8815,9,'A"<','A<Hm','B','6}9=','6dn','Bz','BZLRI','cgzh','D','DAHG','dd','dsjny','DYox','E','e','edeof','eP1h0','Epy','esg','FS','FSNxm','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','iGl','ijhFf','Int','J]gL6','J29T','JaGwu','JF','jlf6','JSAQ','jx','KFE','khMO','KQGPY','KVN','kwe','L','l6','LanZD','m','MAZE','miae','MoP','ms','MWL','mZ2','N','ncadn','NCWe9','nr','O','o','oES','Of','oJXM','p','Pa.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','Rx,M','rya','S4h','szKO','ten','tfryk','tjRha','tU','V','VDYe','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#Vo','ZCQ','zgAz','ZGYLU','zt','ZV0K'] );
};

subtest 'Rule "sc<"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('sc<', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}eN<b','}Gmi','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4xa',6,639,66,'6DGU',7,796,'7b4Xx',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','<gzh','D','DAHG','dd','dsjny','DYox','E','e','edeof','eP1h0','Epy','esg','FS','FSNxm','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','iGl','ijhFf','Int','J]gLb','J29T','JaGwu','JF','jlfb','JSAQ','jx','KFE','khMO','KQGPY','KVN','kwe','L','l6','LanZD','m','MAZE','miae','MoP','ms','MWL','mZ2','N','n<adn','NCWe9','nr','O','o','oES','Of','oJXM','p','Pa.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','Rx,M','rya','S4h','szKO','ten','tfryk','tjRha','tU','V','VDYe','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#Vo','ZCQ','zgAz','ZGYLU','zt','ZV0K'] );
};

subtest 'Rule "sc{"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('sc{', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}eN{b','}Gmi','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4xa',6,639,66,'6DGU',7,796,'7b4Xx',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','{gzh','D','DAHG','dd','dsjny','DYox','E','e','edeof','eP1h0','Epy','esg','FS','FSNxm','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','iGl','ijhFf','Int','J]gLb','J29T','JaGwu','JF','jlfb','JSAQ','jx','KFE','khMO','KQGPY','KVN','kwe','L','l6','LanZD','m','MAZE','miae','MoP','ms','MWL','mZ2','N','n{adn','NCWe9','nr','O','o','oES','Of','oJXM','p','Pa.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','Rx,M','rya','S4h','szKO','ten','tfryk','tjRha','tU','V','VDYe','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#Vo','ZCQ','zgAz','ZGYLU','zt','ZV0K'] );
};

subtest 'Rule "se3"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('se3', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}3Ncb','}Gmi','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4xa',6,639,66,'6DGU',7,796,'7b4Xx',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','cgzh','D','DAHG','dd','dsjny','DYox','E',3,'3d3of','3P1h0','Epy','3sg','FS','FSNxm','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','iGl','ijhFf','Int','J]gLb','J29T','JaGwu','JF','jlfb','JSAQ','jx','KFE','khMO','KQGPY','KVN','kw3','L','l6','LanZD','m','MAZE','mia3','MoP','ms','MWL','mZ2','N','ncadn','NCW39','nr','O','o','oES','Of','oJXM','p','Pa.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','Rx,M','rya','S4h','szKO','t3n','tfryk','tjRha','tU','V','VDY3','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#Vo','ZCQ','zgAz','ZGYLU','zt','ZV0K'] );
};

subtest 'Rule "sg9"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('sg9', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}eNcb','}Gmi','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4xa',6,639,66,'6DGU',7,796,'7b4Xx',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','c9zh','D','DAHG','dd','dsjny','DYox','E','e','edeof','eP1h0','Epy','es9','FS','FSNxm','fvhr','FY','G','Gf','9FHpD','hF','HGGQO','HYH','iGl','ijhFf','Int','J]9Lb','J29T','JaGwu','JF','jlfb','JSAQ','jx','KFE','khMO','KQGPY','KVN','kwe','L','l6','LanZD','m','MAZE','miae','MoP','ms','MWL','mZ2','N','ncadn','NCWe9','nr','O','o','oES','Of','oJXM','p','Pa.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','Rx,M','rya','S4h','szKO','ten','tfryk','tjRha','tU','V','VDYe','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#Vo','ZCQ','z9Az','ZGYLU','zt','ZV0K'] );
};

subtest 'Rule "si1"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('si1', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}eNcb','}Gm1','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4xa',6,639,66,'6DGU',7,796,'7b4Xx',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','cgzh','D','DAHG','dd','dsjny','DYox','E','e','edeof','eP1h0','Epy','esg','FS','FSNxm','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','1Gl','1jhFf','Int','J]gLb','J29T','JaGwu','JF','jlfb','JSAQ','jx','KFE','khMO','KQGPY','KVN','kwe','L','l6','LanZD','m','MAZE','m1ae','MoP','ms','MWL','mZ2','N','ncadn','NCWe9','nr','O','o','oES','Of','oJXM','p','Pa.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','Rx,M','rya','S4h','szKO','ten','tfryk','tjRha','tU','V','VDYe','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#Vo','ZCQ','zgAz','ZGYLU','zt','ZV0K'] );
};

subtest 'Rule "si!"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('si!', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}eNcb','}Gm!','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4xa',6,639,66,'6DGU',7,796,'7b4Xx',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','cgzh','D','DAHG','dd','dsjny','DYox','E','e','edeof','eP1h0','Epy','esg','FS','FSNxm','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','!Gl','!jhFf','Int','J]gLb','J29T','JaGwu','JF','jlfb','JSAQ','jx','KFE','khMO','KQGPY','KVN','kwe','L','l6','LanZD','m','MAZE','m!ae','MoP','ms','MWL','mZ2','N','ncadn','NCWe9','nr','O','o','oES','Of','oJXM','p','Pa.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','Rx,M','rya','S4h','szKO','ten','tfryk','tjRha','tU','V','VDYe','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#Vo','ZCQ','zgAz','ZGYLU','zt','ZV0K'] );
};

subtest 'Rule "so0"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('so0', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}eNcb','}Gmi','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4xa',6,639,66,'6DGU',7,796,'7b4Xx',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','cgzh','D','DAHG','dd','dsjny','DY0x','E','e','ede0f','eP1h0','Epy','esg','FS','FSNxm','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','iGl','ijhFf','Int','J]gLb','J29T','JaGwu','JF','jlfb','JSAQ','jx','KFE','khMO','KQGPY','KVN','kwe','L','l6','LanZD','m','MAZE','miae','M0P','ms','MWL','mZ2','N','ncadn','NCWe9','nr','O',0,'0ES','Of','0JXM','p','Pa.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','Rx,M','rya','S4h','szKO','ten','tfryk','tjRha','tU','V','VDYe','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#V0','ZCQ','zgAz','ZGYLU','zt','ZV0K'] );
};

subtest 'Rule "sq9"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('sq9', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}eNcb','}Gmi','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4xa',6,639,66,'6DGU',7,796,'7b4Xx',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','cgzh','D','DAHG','dd','dsjny','DYox','E','e','edeof','eP1h0','Epy','esg','FS','FSNxm','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','iGl','ijhFf','Int','J]gLb','J29T','JaGwu','JF','jlfb','JSAQ','jx','KFE','khMO','KQGPY','KVN','kwe','L','l6','LanZD','m','MAZE','miae','MoP','ms','MWL','mZ2','N','ncadn','NCWe9','nr','O','o','oES','Of','oJXM','p','Pa.Uu','PP','Pu','PUEKG',9,'QA','QHN','R','rj','Rx,M','rya','S4h','szKO','ten','tfryk','tjRha','tU','V','VDYe','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','Y9Fw','YY','Z\'#Vo','ZCQ','zgAz','ZGYLU','zt','ZV0K'] );
};

subtest 'Rule "ss5"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('ss5', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}eNcb','}Gmi','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4xa',6,639,66,'6DGU',7,796,'7b4Xx',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','cgzh','D','DAHG','dd','d5jny','DYox','E','e','edeof','eP1h0','Epy','e5g','FS','FSNxm','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','iGl','ijhFf','Int','J]gLb','J29T','JaGwu','JF','jlfb','JSAQ','jx','KFE','khMO','KQGPY','KVN','kwe','L','l6','LanZD','m','MAZE','miae','MoP','m5','MWL','mZ2','N','ncadn','NCWe9','nr','O','o','oES','Of','oJXM','p','Pa.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','Rx,M','rya','S4h','5zKO','ten','tfryk','tjRha','tU','V','VDYe','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#Vo','ZCQ','zgAz','ZGYLU','zt','ZV0K'] );
};

subtest 'Rule "ss$"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('ss$', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}eNcb','}Gmi','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4xa',6,639,66,'6DGU',7,796,'7b4Xx',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','cgzh','D','DAHG','dd','d$jny','DYox','E','e','edeof','eP1h0','Epy','e$g','FS','FSNxm','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','iGl','ijhFf','Int','J]gLb','J29T','JaGwu','JF','jlfb','JSAQ','jx','KFE','khMO','KQGPY','KVN','kwe','L','l6','LanZD','m','MAZE','miae','MoP','m$','MWL','mZ2','N','ncadn','NCWe9','nr','O','o','oES','Of','oJXM','p','Pa.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','Rx,M','rya','S4h','$zKO','ten','tfryk','tjRha','tU','V','VDYe','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#Vo','ZCQ','zgAz','ZGYLU','zt','ZV0K'] );
};

subtest 'Rule "st7"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('st7', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}eNcb','}Gmi','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4xa',6,639,66,'6DGU',7,796,'7b4Xx',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','cgzh','D','DAHG','dd','dsjny','DYox','E','e','edeof','eP1h0','Epy','esg','FS','FSNxm','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','iGl','ijhFf','In7','J]gLb','J29T','JaGwu','JF','jlfb','JSAQ','jx','KFE','khMO','KQGPY','KVN','kwe','L','l6','LanZD','m','MAZE','miae','MoP','ms','MWL','mZ2','N','ncadn','NCWe9','nr','O','o','oES','Of','oJXM','p','Pa.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','Rx,M','rya','S4h','szKO','7en','7fryk','7jRha','7U','V','VDYe','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#Vo','ZCQ','zgAz','ZGYLU','z7','ZV0K'] );
};

subtest 'Rule "st+"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('st+', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}eNcb','}Gmi','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4xa',6,639,66,'6DGU',7,796,'7b4Xx',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','cgzh','D','DAHG','dd','dsjny','DYox','E','e','edeof','eP1h0','Epy','esg','FS','FSNxm','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','iGl','ijhFf','In+','J]gLb','J29T','JaGwu','JF','jlfb','JSAQ','jx','KFE','khMO','KQGPY','KVN','kwe','L','l6','LanZD','m','MAZE','miae','MoP','ms','MWL','mZ2','N','ncadn','NCWe9','nr','O','o','oES','Of','oJXM','p','Pa.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','Rx,M','rya','S4h','szKO','+en','+fryk','+jRha','+U','V','VDYe','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#Vo','ZCQ','zgAz','ZGYLU','z+','ZV0K'] );
};

subtest 'Rule "sx%"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('sx%', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}eNcb','}Gmi','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4%a',6,639,66,'6DGU',7,796,'7b4X%',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','cgzh','D','DAHG','dd','dsjny','DYo%','E','e','edeof','eP1h0','Epy','esg','FS','FSN%m','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','iGl','ijhFf','Int','J]gLb','J29T','JaGwu','JF','jlfb','JSAQ','j%','KFE','khMO','KQGPY','KVN','kwe','L','l6','LanZD','m','MAZE','miae','MoP','ms','MWL','mZ2','N','ncadn','NCWe9','nr','O','o','oES','Of','oJXM','p','Pa.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','R%,M','rya','S4h','szKO','ten','tfryk','tjRha','tU','V','VDYe','VkX','VNT','w','wQ','wWGYY','WY3l','%HlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#Vo','ZCQ','zgAz','ZGYLU','zt','ZV0K'] );
};

subtest 'Rule ""' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('', \@plains)], [] );
};

subtest 'Rule "## rule: leetspeak multi"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('## rule: leetspeak multi', \@plains)], [] );
};

subtest 'Rule "## limits: none"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('## limits: none', \@plains)], [] );
};

subtest 'Rule "## example: johnbox ---> j0hnbox"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('## example: johnbox ---> j0hnbox', \@plains)], [] );
};

subtest 'Rule "## extras: all case variants"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('## extras: all case variants', \@plains)], [] );
};

subtest 'Rule ""' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('', \@plains)], [] );
};

subtest 'Rule "sa@sc<se3si1so0ss$"' => sub {
	is_deeply( [$rulesEngine->gen_single_rule('sa@sc<se3si1so0ss$', \@plains)], ['\'','\'/','-','$<"(','&','&?','("}*','*@_','*`','*+(+','.M','/;,',';?&],','?\\${,','?+**','@>+]/','[{','_%+','}','}3N<b','}Gm1','~-.=,','~@','+.A','>?,',0,'0800',1,10215,11087,12190,200,222,2395,26257,'3M','3yknr',4381,47,'4x@',6,639,66,'6DGU',7,796,'7b4Xx',81,84,8815,9,'A"<','A<Hm','B','b}9=','bdn','Bz','BZLRI','<gzh','D','DAHG','dd','d$jny','DY0x','E',3,'3d30f','3P1h0','Epy','3$g','FS','FSNxm','fvhr','FY','G','Gf','gFHpD','hF','HGGQO','HYH','1Gl','1jhFf','Int','J]gLb','J29T','J@Gwu','JF','jlfb','JSAQ','jx','KFE','khMO','KQGPY','KVN','kw3','L','l6','L@nZD','m','MAZE','m1@3','M0P','m$','MWL','mZ2','N','n<@dn','NCW39','nr','O',0,'0ES','Of','0JXM','p','P@.Uu','PP','Pu','PUEKG','q','QA','QHN','R','rj','Rx,M','ry@','S4h','$zKO','t3n','tfryk','tjRh@','tU','V','VDY3','VkX','VNT','w','wQ','wWGYY','WY3l','xHlI','XPJP','XQ','y','y2K','YqFw','YY','Z\'#V0','ZCQ','zgAz','ZGYLU','zt','ZV0K'] );
};


done_testing();
