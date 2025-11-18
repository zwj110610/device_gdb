SECTIONS
{
  .itcm : {
    *(.text.itcm .text.itcm.*)
  }

  .dtcm.ro : {
    *(.dtcm.ro .dtcm.ro.*)
  }

  .dtcm.data : {
    *(.dtcm.data .dtcm.data.*)
  }
}
INSERT AFTER .text;
