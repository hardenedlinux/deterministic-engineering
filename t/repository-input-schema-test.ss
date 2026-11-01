;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import
  :std/test
  (only-in :clan/poo/object .get)
  (only-in :clan/poo/mop TypeError?)
  (only-in "../library/drivers/project-formation/inputs.ss"
    formation-acquire-inputs formation-input-observation formation-inputs-current!))
(export repository-input-schema-test)

(def repository-input-schema-test
  (test-suite "Yuanxu Schema at the existing repository acquisition boundary"
    (test-case "actual repository inputs retain the native currentness owner"
      (def acquired (formation-acquire-inputs (current-directory) '("gerbil.pkg") 16777216 120))
      (def observation (formation-input-observation acquired))
      (check-equal? (.get observation status) 'repository-observation)
      (check-equal? (length (.get observation inputs)) 1)
      (check-equal? (eq? (formation-inputs-current! acquired) acquired) #t))
    (test-case "native Schema rejects structure, cardinality, duplicates and bounds"
      (for-each
        (lambda (arguments)
          (check-exception (apply formation-acquire-inputs arguments) TypeError?))
        (list
          (list "" '("gerbil.pkg") 1024 10)
          (list (current-directory) '() 1024 10)
          (list (current-directory) '("gerbil.pkg" "gerbil.pkg") 1024 10)
          (list (current-directory) '(7) 1024 10)
          (list (current-directory) '("gerbil.pkg") 0 10)
          (list (current-directory) '("gerbil.pkg") 16777217 10)
          (list (current-directory) '("gerbil.pkg") 1024 0)
          (list (current-directory) '("gerbil.pkg") 1024 121))))
    (test-case "filesystem semantics remain stricter than JSON shape"
      (check-exception
        (formation-acquire-inputs (current-directory) '("../gerbil.pkg") 1024 10)
        (lambda (_) #t))
      (check-exception
        (formation-acquire-inputs (current-directory) '("gerbil.pkg") 1024.0 10)
        (lambda (_) #t)))))
