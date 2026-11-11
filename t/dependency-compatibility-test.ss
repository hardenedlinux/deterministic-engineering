;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
;;; A small native ASCENT evaluation checks the shared POO object ABI.
;;; The literal answers are an independent finite oracle, not gateway gold.
(import :std/test :gerbil-ascent/rules/func
        (only-in :gerbil-ascent/rules/declaration rule-module-program)
        (only-in :clan/poo/object .o .ref))

(define-program (make-compatibility-evidence)
  (sources input)
  (outputs answer)
  (relation input ((value integer?)))
  (relation answer ((value integer?)))
  ((answer X) <-- (input X) (if (X) (< X 2))))

(def (with-input schema input-rows (rules? #t))
  (def program (rule-module-program schema))
  (gerbil-ascent-program
    (map (lambda (relation)
           (if (eq? (.ref relation 'name) 'input)
             (.o (:: @ relation) rows: input-rows)
             relation))
         (.ref program 'relations))
    (if rules? (.ref program 'rules) '())))

(def (main . _args)
  (def schema (make-compatibility-evidence))
  (for-each
    (lambda (workers)
      (def result (gerbil-ascent-evaluate-program
                    (with-input schema '((0) (1) (2))) workers: workers))
      (def answers (list-sort (lambda (a b) (< (car a) (car b)))
                             ((.ref result 'rows-of) 'answer)))
      (unless (equal? answers '((0) (1)))
        (error "ASCENT compatibility oracle mismatch" workers answers)))
    '(1 2))
  (def empty-result (gerbil-ascent-evaluate-program (with-input schema '((3)))))
  (unless (null? ((.ref empty-result 'rows-of) 'answer))
    (error "a separate evaluation retained an earlier answer"))
  ;; A matched no-rule control isolates source typing from the numeric rule.
  (def typed-only (gerbil-ascent-evaluate-program (with-input schema '((3)) #f)))
  (unless (equal? ((.ref typed-only 'rows-of) 'input) '((3)))
    (error "typed source control did not retain its input"))
  (unless (with-catch (lambda (_failure) #t)
            (lambda ()
              (gerbil-ascent-evaluate-program (with-input schema '(("invalid")) #f))
              #f))
    (error "typed relation accepted an invalid input"))
  (displayln "DEPENDENCY-COMPATIBILITY-OK"))

(export dependency-compatibility-test)
(def dependency-compatibility-test
  (test-suite "dependency-compatibility-test"
    (test-case "native qualification" (main))))
