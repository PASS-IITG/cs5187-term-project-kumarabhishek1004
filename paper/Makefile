main.pdf: main.tex macros.tex references.bib sections/*.tex figures/*.tex
	pdflatex -interaction=nonstopmode main
	-bibtex main   # "-": no \cite yet must not stop the build
	pdflatex -interaction=nonstopmode main
	pdflatex -interaction=nonstopmode main

check: main.pdf
	sh scripts/check.sh

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.toc main.pdf

.PHONY: clean check
