# HB-Eval V2 | خطة التنفيذ وسجل الأدلة
تحديث 20 نوفمبر 2026. بعد كل دفعة حدّث هذا الملف وأرفق رابطه وملخص ما تم ودليله والخطوة التالية في تسليم العمل.

| المرحلة | ما تم ودليله | التالي |
|---|---|---|
| توحيد التجارب | فرع المراجعة يجمع ملفات 17 و16 واختبار العامل المنتظر من 15 باسم مستقل. | التحقق من CI ومراجعة الدمج. |
| قياس الأثر | قاعدة للمزوّد منفصلة عن البوابة. سجل للمحاولات وجدول للآثار ومعرف إيصال لكل رد. كشف الضابط غير المحمي أثرين. | التحقق من نفس العد لدى مزوّد sandbox مستقل. |
| التجربة الرابعة | خمس حالات × ثلاث سياسات محلية. إعادة إرسال من عملية جديدة، تغيير المبلغ، سباق عمليتين بحاجز، تغيير المفتاح، وتعذر الاستعلام. | اختبار تأخر الظهور ثم التسوية، عزل العملاء، صلاحية المفتاح، وتعارض العملة. |
| المقارنة | شغّلت الحالات نفسها لسياسات raw وprovider وgateway. الضبط التجريبي محلي. | قياس زمن الحسم، التأكيد الخاطئ وكلفة التدخل في مسار تشغيل متكامل. |
| تجربة خارجية | معلقة. | اختيار مزوّد، واستخدام حساب اختبار ثم مطابقة العمليات مع سجل المزوّد. |
| جواز الموثوقية | اختبارات النطاق للدفع والشحن موجودة. | توثيق العمر والتغطية والإصدارات والاعتمادات العابرة، وقياس التراجعات الفائتة مقابل الاختبار الكامل. |

Local reproduction: Python 3.12.14, SQLite 3.53.1, pytest 9.2.0. From repository root run:

    python -m pytest -q tests/test_refund_evidence.py tests/test_shipment_evidence.py tests/test_refund_worker_restart.py tests/test_refund_waiting_worker.py tests/test_refund_dispatch.py

23 passed locally. For retry and conflict tests the first worker exits after commit and before reply. Both race workers observe zero effects before crossing the barrier. Under retry and race, raw produced two effects, provider and gateway one. Under changed key, raw and provider produced two, gateway one. Under opaque provider the gateway returned UNKNOWN. These results describe a simulator with modeled provider semantics and a test-only policy. No external payment was executed.

## تحديث دفعة التسوية وحدود الهوية
- اكتملت محلياً خمس حالات إضافية، وأصبح مجموع الاختبارات المركزة 28 ناجحة. انتقلت العملية بعد ثلاث قراءات UNKNOWN إلى CONFIRMED بالإيصال الصحيح، وبقي عداد الإرسال واحداً بعد كل قراءة.
- اختبرنا الساعة الافتراضية قبل انتهاء حماية المفتاح، وعند الحد وبعده، وتعارض العملة واستقلال عميلين يحملان نفس مرجع العملية والمفتاح.
- أضيف tests/test_stripe_refund_sandbox.py لمسار HTTP تجريبي داخل تطبيق البوابة في الاختبار مع مقارنة إيصال POST بسجل GET لدى Stripe. يوجد اختبار نقل محاكى مستقل. التشغيل الخارجي معلق على STRIPE_TEST_SECRET_KEY وHB_REFUND_TEST_CHARGE لدفعة USD اختبارية ناجحة غير مستردة. ينفذ رد سنت واحد تجريبي. لا تُسجل المفاتيح هنا. التالي تشغيل الحالة الخارجية في بيئة أسرار ثم إرفاق نتيجة المطابقة. مسار الاختبار خاص بالاختبار وليس منشوراً.
