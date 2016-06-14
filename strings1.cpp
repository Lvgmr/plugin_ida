#define __EA64__

#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <entry.hpp>	
#include <offset.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <xref.hpp>
#include <ua.hpp>
#include <algorithm>
#include <allins.hpp>
#include <fixup.hpp>

/**
@mainpage Этот плагин следует использовать следующим образом:
сначала его нужно собирать в VisualStudio 10.0, с необходимыми параметрами сборки,
которые приведены в первой главе вкр, а потом полученный plw
скопировать в папку с IDA PRO /plugins
*/ 

/**
@struct eat 
Структура, в которую сохраняются все необходимые значения
Данная структура была создана для удобства работы с va, rva, offset и т.д. 
*/
	typedef struct eat { 
		qstring name;
		bool	bbs_type;
		ea_t	va,
				rva,
				offset,
				bbs_size;
		bool	bb_start,
				insn_need; 
	};

/**
@function get_size(ea_t)
Необходима для определения размера базового блока.
@param[in] адрес начала базового блока
@param[out] размер базового блока
*/
static ea_t get_size(ea_t start)
{
	ea_t ea1 = start;
	ua_ana0(ea1);
	while (true)
    {
		ea1 = get_item_end(ea1);
		if (!ua_ana0(ea1))
			break;
		if (is_basic_block_end(true))
			break;
    }
	//ea1 = get_item_end(ea1);
	return (ea1 - start);
}


/**
@function get_type(ea_t)
Необходима для определения типа базового блока.
@param[in] адрес начала базового блока
@param[out] true - если блок кода, false - блок данных
*/
static bool get_type(ea_t start)
{
	flags_t flags = get_flags_novalue(start);
		if (isCode(flags))
			return true;
		if (isData(flags))
			return false;
}

int idaapi IDAP_init(void)
{
	if(inf.filetype != f_PE)
	{
		error("Only PE binary type compiled for the x86 platform is supported, sorry.");
		return PLUGIN_SKIP; 
	}
	else
		return PLUGIN_KEEP;
}
/**
@function IDAP_term
Необходима, например, для освобождения динамической памяти 
или файловых дескрипторов, которые были задействованы в 
процессе работы плагина.
@param[out] выполняется при выходе из плагина
*/
void idaapi IDAP_term(void)
{
 return;
}

// Через файл plugins.cfg в плагин могут быть переданы целые 
// аргументы

void idaapi IDAP_run(int arg)
{
	eat str;
	qvector<eat> MAC;
	int nseg = get_segm_qty();
	int j = 1;
	FILE *file1, *file2, *file3, *binfile, *binfile2, *binfile3;
	file1 = qfopen("D:\\new\\1.txt","w");
	file2 = qfopen("D:\\new\\2.txt","w");
	file3 = qfopen("D:\\new\\3.txt","w");
	binfile = qfopen("D:\\new\\binoutput.bin", "wb");
	binfile2 = qfopen("D:\\new\\binoutput_table.bin", "wb");
	

/**PART3*/
	/**Поиск всех адресов*/
	for (int i = 0; i < get_segm_qty(); i++) 
		{ 
		 char segName[MAXSTR];
		 segment_t *seg = getnseg(i); 
		 get_segm_name(seg, segName, sizeof(segName)-1); 
		 ea_t start = seg->startEA;
			while(start <= seg->endEA) 
			{
				/**Получение смещения*/
				ea_t offset = get_fileregion_offset(start);
				/**Получение rva*/
				ea_t virtual_address = start - get_imagebase();
				/**Получение va*/
				ea_t va = virtual_address + get_imagebase();
				str.name = segName; str.va = va; str.rva = virtual_address; str.offset = offset;
				qfprintf(file2,"| % *s | %x | % *x | % *x |\n", 8, segName, start, 5, virtual_address, 8, offset);
				qfwrite(binfile2, &start, sizeof(ea_t));
				qfwrite(binfile2, &virtual_address, sizeof(ea_t));
				qfwrite(binfile2, &offset, sizeof(ea_t));
				MAC.push_back(str);
				start = nextaddr(start);	
			}
		} 
		qfclose(file2);
		qfclose(binfile2);

		xrefblk_t xb;
		ea_t insn1 = get_screen_ea();
		for (bool res = xb.first_to(insn1, XREF_FAR); res; res = xb.next_to()) 
				{
					msg("From: %a, To: %a\n", xb.from, xb.to);
					msg("Type: %d, IsCode: %d\n", xb.type, xb.iscode);
				}

/**PART1*/qvector<ea_t> address, ready;FILE *file_new;
file_new = qfopen("D:\\new\\4.txt","w");

for (int i = 0; i < MAC.size(); i++){	MAC.at(i).bb_start = false;	MAC.at(i).insn_need = false;}

/**Запись в структуру адреса точки входа в программу*/
for (int e = 0; e < get_entry_qty(); e++)
{
	ea_t startaddr = get_entry(get_entry_ordinal(e));
	address.push_back(startaddr);	for (int i = 0; i < MAC.size(); i++)		if (MAC.at(i).va == startaddr)			MAC.at(i).bb_start = true;			}show_wait_box("Finding basic blocks");/**Поиск базовых блоков*/while (address.empty() != true) { 	ea_t current = address.back();	for (int j = 0; j < ready.size(); j++)		if (ready.at(j) == current)		{			address.del(current);			current = get_item_end(current);			address.push_back(current);			continue;		}	/**Если адресс некорректный*/	if (!(decode_insn(current) > 0))	{		address.del(current);		continue;	}	/**Если инструкция ret*/	if (is_ret_insn(current)) 	{		address.del(current);		continue;	}	/**Если конец базового блока*/	if (is_basic_block_end(true))	{		ea_t insn = cmd.Operands[0].addr;		bool usl = false;				for (int j = 0; j < ready.size(); j++)			if (ready.at(j) == insn)				usl = true;						for (int j = 0; j < MAC.size(); j++)			if (MAC.at(j).va == current)				MAC.at(j).insn_need = true;							if (usl == false && (decode_insn(insn)>0))			address.push_back(insn);		for (int i = 0; i < MAC.size(); i++)			if (MAC.at(i).va == insn)			{				MAC.at(i).bb_start = true;				MAC.at(i).bbs_size = get_size(insn);				MAC.at(i).bbs_type = get_type(insn);							}			ea_t next = get_item_end(current);			/**Определение размера базового блока, на который указывает инструкция перехода*/			if (ua_ana0(next))				for (int i = 0; i < MAC.size(); i++)					if (MAC.at(i).va == next)					{						MAC.at(i).bb_start = true;						MAC.at(i).bbs_size = get_size(next);						MAC.at(i).bbs_type = get_type(next);					}	}	address.del(current);	ready.push_back(current);	current = get_item_end(current);	address.push_back(current);}hide_wait_box();/**Запись в файл*/FILE* binfile_bbs;binfile_bbs = qfopen("D:\\new\\part1.bin","wb");for (int i = 0; i< MAC.size(); i++)	if (MAC.at(i).bb_start == true)	{		qfprintf(file_new, "Address of basic block : %a\n", i, MAC.at(i).va);		qfwrite(binfile_bbs, &MAC.at(i).va, sizeof(ea_t));		qfwrite(binfile_bbs, &MAC.at(i).bbs_type, sizeof(bool));		qfwrite(binfile_bbs, &MAC.at(i).bbs_size, sizeof(ea_t));		msg("Basic blok start : %a size of basic block : %a, type : %d\n", MAC.at(i).va, MAC.at(i).bbs_size, MAC.at(i).bbs_type);	}qfclose(binfile_bbs);/*qfclose(file_new);	FILE *newfile;
	newfile = qfopen("D:\\new\\READY_FILE.txt","w");
	qfprintf(newfile,"+----------+--------+-------+----------+-----------+-------+\n");
	qfprintf(newfile,"|   Name   |   Va   |  Rva  |  Offset  |  StartBB  |  AOR  |\n");
	qfprintf(newfile,"+----------+--------+-------+----------+-----------+-------+\n");

	for (int i = 0; i < MAC.size(); i++)
	{
		qfprintf(newfile,"| % *s |", 8, MAC.at(i).name);
		qfprintf(newfile," %a |", MAC.at(i).va);
		qfprintf(newfile," % *x | % *x |", 5, MAC.at(i).rva, 8, MAC.at(i).offset);
		if (MAC.at(i).bb_start == true)
			qfprintf(newfile,"      yes  |");
		else qfprintf(newfile,"           |");
		if (MAC.at(i).insn_need == true)
			qfprintf(newfile,"  yes  |\n");
		else qfprintf(newfile,"       |\n");
	}
	
	qfclose(newfile);
	*/
	
/**----------------------------------------------------------------------------------------------------------------------------
-------------------------------PART-2-----------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------------------*/
/** Набор инструкций, которые могут хранить абсолютный или относительный адрес*/	
int insn_m[] = { NN_call, NN_jmp, NN_jg, NN_jnle, NN_jge, NN_jnl, NN_jl, NN_jnge, NN_jno, NN_jns, NN_jo, NN_js, NN_ja, NN_jnbe,
 NN_jae, NN_jnb, NN_jbe, NN_jna, NN_jc, NN_je, NN_jz, NN_jnc, NN_jne, NN_jnz, NN_jnp, NN_jpo, NN_jp, NN_jpe, NN_loopw, NN_loop, NN_loopd, NN_loopq,
NN_loopwe, NN_loope, NN_loopde, NN_loopqe, NN_loopwne, NN_loopne, NN_loopdne, NN_loopqne, 0 };
binfile3 = qfopen("D:\\new\\part2.bin", "wb");
ea_t fl = 0;
int need_seg = get_segm_qty();
for (int i = 0; i < nseg; i++)
{
	segment_t *s = getnseg(i);
	//if (s->type == SEG_DATA)
	//{
		ea_t start = s->startEA;
		/**Проход по всем адресам*/
		while ( start <= s->endEA)
		{
			/**Разбор инструкции*/
			decode_insn(start);
			if (is_basic_block_end(true))
			{
				/**Абсолютный адрес инструкции*/
				ea_t insn = cmd.Op1.addr;
				
				for (int i = 0; insn_m[i] != 0; i++)
				{
					if (cmd.itype == insn_m[i])
					{
						qfwrite(binfile3, &start, sizeof(ea_t));
						if (decode_insn(insn))
							qfwrite(binfile3, &insn, sizeof(ea_t));
						else qfwrite(binfile3, &fl, sizeof(ea_t));
					}
				}
			}
			start = nextaddr(start);
		}
	//}
}
qfclose(binfile3);

}


/** Строка задает описание плагина, доступное из IDA*/
char IDAP_comment[] = "This is my test plug-in";
char IDAP_help[] = "My plugin";

/** Строка задает имя плагина, отображаемое в меню Edit->Plugins menu.*/
char IDAP_name[] = "My plugin";

/** Комбинация клавиш для быстрого вызова плагина в IDA*/
char IDAP_hotkey[] = "Alt-V";

/** Объект PLUGIN*/
plugin_t PLUGIN =
{
 IDP_INTERFACE_VERSION, // Версия IDA, для которой 
                        // предназначен плагин 
 0,                     // Флаги
 IDAP_init,             // Функция инициализации
 IDAP_term,             // Функция “очистки”
 IDAP_run,              // Основное “тело” плагина 
 IDAP_comment,          // Комментарии
 IDAP_help,             // Помощь
 IDAP_name,             // Имя плагина
 IDAP_hotkey            // Комбинация “горячих” клавиш
};

