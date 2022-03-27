if exists("b:current_syntax")
  finish
endif


syn keyword minkcfgFields TYPES CONFIG
syn keyword minkcfgConsts METHOD SCRIPT CONST
syn keyword minkcfgConsts PTRN contained
syn match minkcfgOp "\[" contained
syn match minkcfgOp "\]" contained
syn match minkcfgOp "{"
syn match minkcfgConsts "*"
syn match minkcfgConsts "/S/"
syn match minkcfgOp "}"
syn match minkcfgComment2 "//.*$"
syn match minkcfgString '".\{-}"'
syn match minkcfgRegex "PTRN.\{-}PTRN" contains=minkcfgConsts
syn match minkcfgRegex "\[.\{-}\]" contains=minkcfgOp
syn region minkcfgComment2 start="/\*" end="\*/"

let b:current_syntax = "minkcfg"

hi def link minkcfgComment2 Comment
hi def link minkcfgKeywords Constant
hi def link minkcfgString Constant
hi def link minkcfgConsts Type
hi def link minkcfgFields Statement
hi def link minkcfgActions Constant
hi def link minkcfgNodeTypes PreProc
hi def link minkcfgOp PreProc
hi def link minkcfgRegex PreProc

hi def link minkcfgExpr Type
hi def link minkcfgEvalTrue Type
hi def link minkcfgEvalFalse Type

hi def link minkcfgAttr Comment
hi def link minkcfgStmt Type
hi def link minkcfgColon1 Type
hi def link minkcfgColon2 Type


