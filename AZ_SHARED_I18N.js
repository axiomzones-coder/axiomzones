/* ══════════════════════════════════════════════════════════════════
   AZ_SHARED_I18N.js — مكتبة الترجمة المشتركة عبر كل منصات Axiom Zones
   ══════════════════════════════════════════════════════════════════

   الهدف: نصوص متكررة عبر كل المنصات (أزرار عامة، أشهر، أيام، رسائل
   نظام عامة) تُترجَم مرة واحدة هنا، بدل إعادة ترجمتها من الصفر في كل
   منصة جديدة تُبنى.

   ── كيفية الاستخدام في أي منصة ──
   1) أضف قبل وسم إغلاق </head> في ملف المنصة:
        <script src="/AZ_SHARED_I18N.js"></script>
      (لازم تكون قبل سكريبت المنصة نفسه اللي فيه دالة الترجمة t())

   2) داخل دالة الترجمة t(key) الخاصة بالمنصة، أضف هذا كخط احتياطي
      أخير (بعد فشل البحث في STATIC المحلية للمنصة، وقبل أي fallback
      يدوي كان موجوداً):

        function t(key) {
          var lang = CURRENT_LANG || 'ar';
          // 1) ابحث أولاً في ترجمة المنصة المحلية (كما هو معتاد)
          if (STATIC[lang] && STATIC[lang][key]) return STATIC[lang][key];
          // 2) لو غير موجود محلياً، ابحث في المكتبة المشتركة (جديد)
          if (typeof AZ_SHARED_I18N !== 'undefined') {
            if (AZ_SHARED_I18N[lang] && AZ_SHARED_I18N[lang][key]) return AZ_SHARED_I18N[lang][key];
            // سلسلة الاحتياطي المعتمدة: اللغة المطلوبة → الإنجليزية → العربية
            if (AZ_SHARED_I18N.en && AZ_SHARED_I18N.en[key]) return AZ_SHARED_I18N.en[key];
            if (AZ_SHARED_I18N.ar && AZ_SHARED_I18N.ar[key]) return AZ_SHARED_I18N.ar[key];
          }
          // 3) لا يوجد أي ترجمة — أرجع المفتاح نفسه (يظهر وضوحاً أنه مفقود، لا نص فارغ)
          return key;
        }

   3) في HTML، استخدم data-i18n بنفس الطريقة المعتادة، بمفتاح من هذه
      المكتبة (كلها تبدأ بـ "shared."):
        <button data-i18n="shared.start">ابدأ الآن</button>

   ── إضافة لغة جديدة مستقبلاً ──
   أضف كائن اللغة الجديد بنفس المفاتيح بالضبط (انسخ كائن "en" كقالب)،
   لا حاجة لتعديل أي منصة تستخدم المكتبة — التحديث هنا يطبَّق تلقائياً
   على كل المنصات التي تستوردها.

   اللغات الحالية: عربي، إنجليزي، فرنسي، تركي، أردو (الخمس الأساسية
   المُترجَمة بالكامل حالياً عبر المنظومة — القسم ㊽ من قاعدة المعرفة).
   ══════════════════════════════════════════════════════════════════ */

var AZ_SHARED_I18N = {

  ar: {
    // ── أزرار دعوة للعمل (CTAs) عامة ──
    'shared.start': 'ابدأ الآن', 'shared.subscribe': 'اشترك الآن', 'shared.tryFree': 'جرّب مجاناً',
    'shared.learnMore': 'اعرف أكثر', 'shared.getStarted': 'ابدأ رحلتك',
    'shared.login': 'تسجيل الدخول', 'shared.signup': 'إنشاء حساب', 'shared.logout': 'تسجيل الخروج',
    'shared.save': 'حفظ', 'shared.cancel': 'إلغاء', 'shared.confirm': 'تأكيد', 'shared.submit': 'إرسال',
    'shared.close': 'إغلاق', 'shared.back': 'رجوع', 'shared.next': 'التالي', 'shared.previous': 'السابق',
    'shared.yes': 'نعم', 'shared.no': 'لا', 'shared.ok': 'حسناً',
    // ── حالات النظام العامة ──
    'shared.loading': 'جاري التحميل...', 'shared.saving': 'جاري الحفظ...', 'shared.sending': 'جاري الإرسال...',
    'shared.success': 'تم بنجاح!', 'shared.error': 'حدث خطأ', 'shared.tryAgain': 'حاول مرة أخرى',
    'shared.comingSoon': 'قريباً', 'shared.free': 'مجاني', 'shared.pro': 'احترافي',
    // ── شارات دائمة عبر كل منصة (القسم ㊺) ──
    'shared.ecosystem': 'المنظومة', 'shared.evolving': '🔄 منصة تتطوّر باستمرار',
    // ── أشهر السنة ──
    'shared.jan':'يناير','shared.feb':'فبراير','shared.mar':'مارس','shared.apr':'أبريل','shared.may':'مايو','shared.jun':'يونيو',
    'shared.jul':'يوليو','shared.aug':'أغسطس','shared.sep':'سبتمبر','shared.oct':'أكتوبر','shared.nov':'نوفمبر','shared.dec':'ديسمبر',
    // ── أيام الأسبوع ──
    'shared.sun':'الأحد','shared.mon':'الإثنين','shared.tue':'الثلاثاء','shared.wed':'الأربعاء','shared.thu':'الخميس','shared.fri':'الجمعة','shared.sat':'السبت',
  },

  en: {
    'shared.start': 'Get Started', 'shared.subscribe': 'Subscribe Now', 'shared.tryFree': 'Try Free',
    'shared.learnMore': 'Learn More', 'shared.getStarted': 'Start Your Journey',
    'shared.login': 'Login', 'shared.signup': 'Sign Up', 'shared.logout': 'Logout',
    'shared.save': 'Save', 'shared.cancel': 'Cancel', 'shared.confirm': 'Confirm', 'shared.submit': 'Submit',
    'shared.close': 'Close', 'shared.back': 'Back', 'shared.next': 'Next', 'shared.previous': 'Previous',
    'shared.yes': 'Yes', 'shared.no': 'No', 'shared.ok': 'OK',
    'shared.loading': 'Loading...', 'shared.saving': 'Saving...', 'shared.sending': 'Sending...',
    'shared.success': 'Success!', 'shared.error': 'An error occurred', 'shared.tryAgain': 'Try Again',
    'shared.comingSoon': 'Coming Soon', 'shared.free': 'Free', 'shared.pro': 'Pro',
    'shared.ecosystem': 'Ecosystem', 'shared.evolving': '🔄 Continuously evolving',
    'shared.jan':'January','shared.feb':'February','shared.mar':'March','shared.apr':'April','shared.may':'May','shared.jun':'June',
    'shared.jul':'July','shared.aug':'August','shared.sep':'September','shared.oct':'October','shared.nov':'November','shared.dec':'December',
    'shared.sun':'Sunday','shared.mon':'Monday','shared.tue':'Tuesday','shared.wed':'Wednesday','shared.thu':'Thursday','shared.fri':'Friday','shared.sat':'Saturday',
  },

  fr: {
    'shared.start': 'Commencer', 'shared.subscribe': "S'abonner", 'shared.tryFree': 'Essayer gratuitement',
    'shared.learnMore': 'En savoir plus', 'shared.getStarted': 'Démarrez votre parcours',
    'shared.login': 'Connexion', 'shared.signup': 'Créer un compte', 'shared.logout': 'Déconnexion',
    'shared.save': 'Enregistrer', 'shared.cancel': 'Annuler', 'shared.confirm': 'Confirmer', 'shared.submit': 'Envoyer',
    'shared.close': 'Fermer', 'shared.back': 'Retour', 'shared.next': 'Suivant', 'shared.previous': 'Précédent',
    'shared.yes': 'Oui', 'shared.no': 'Non', 'shared.ok': "D'accord",
    'shared.loading': 'Chargement...', 'shared.saving': 'Enregistrement...', 'shared.sending': 'Envoi...',
    'shared.success': 'Succès !', 'shared.error': "Une erreur s'est produite", 'shared.tryAgain': 'Réessayer',
    'shared.comingSoon': 'Bientôt disponible', 'shared.free': 'Gratuit', 'shared.pro': 'Pro',
    'shared.ecosystem': 'Écosystème', 'shared.evolving': '🔄 En évolution continue',
    'shared.jan':'Janvier','shared.feb':'Février','shared.mar':'Mars','shared.apr':'Avril','shared.may':'Mai','shared.jun':'Juin',
    'shared.jul':'Juillet','shared.aug':'Août','shared.sep':'Septembre','shared.oct':'Octobre','shared.nov':'Novembre','shared.dec':'Décembre',
    'shared.sun':'Dimanche','shared.mon':'Lundi','shared.tue':'Mardi','shared.wed':'Mercredi','shared.thu':'Jeudi','shared.fri':'Vendredi','shared.sat':'Samedi',
  },

  tr: {
    'shared.start': 'Başlayın', 'shared.subscribe': 'Şimdi Abone Ol', 'shared.tryFree': 'Ücretsiz Dene',
    'shared.learnMore': 'Daha Fazla Bilgi', 'shared.getStarted': 'Yolculuğunuza Başlayın',
    'shared.login': 'Giriş Yap', 'shared.signup': 'Hesap Oluştur', 'shared.logout': 'Çıkış Yap',
    'shared.save': 'Kaydet', 'shared.cancel': 'İptal', 'shared.confirm': 'Onayla', 'shared.submit': 'Gönder',
    'shared.close': 'Kapat', 'shared.back': 'Geri', 'shared.next': 'İleri', 'shared.previous': 'Önceki',
    'shared.yes': 'Evet', 'shared.no': 'Hayır', 'shared.ok': 'Tamam',
    'shared.loading': 'Yükleniyor...', 'shared.saving': 'Kaydediliyor...', 'shared.sending': 'Gönderiliyor...',
    'shared.success': 'Başarılı!', 'shared.error': 'Bir hata oluştu', 'shared.tryAgain': 'Tekrar Dene',
    'shared.comingSoon': 'Yakında', 'shared.free': 'Ücretsiz', 'shared.pro': 'Pro',
    'shared.ecosystem': 'Ekosistem', 'shared.evolving': '🔄 Sürekli gelişiyor',
    'shared.jan':'Ocak','shared.feb':'Şubat','shared.mar':'Mart','shared.apr':'Nisan','shared.may':'Mayıs','shared.jun':'Haziran',
    'shared.jul':'Temmuz','shared.aug':'Ağustos','shared.sep':'Eylül','shared.oct':'Ekim','shared.nov':'Kasım','shared.dec':'Aralık',
    'shared.sun':'Pazar','shared.mon':'Pazartesi','shared.tue':'Salı','shared.wed':'Çarşamba','shared.thu':'Perşembe','shared.fri':'Cuma','shared.sat':'Cumartesi',
  },

  ur: {
    'shared.start': 'شروع کریں', 'shared.subscribe': 'ابھی سبسکرائب کریں', 'shared.tryFree': 'مفت آزمائیں',
    'shared.learnMore': 'مزید جانیں', 'shared.getStarted': 'اپنا سفر شروع کریں',
    'shared.login': 'لاگ ان', 'shared.signup': 'اکاؤنٹ بنائیں', 'shared.logout': 'لاگ آؤٹ',
    'shared.save': 'محفوظ کریں', 'shared.cancel': 'منسوخ کریں', 'shared.confirm': 'تصدیق کریں', 'shared.submit': 'جمع کرائیں',
    'shared.close': 'بند کریں', 'shared.back': 'واپس', 'shared.next': 'اگلا', 'shared.previous': 'پچھلا',
    'shared.yes': 'ہاں', 'shared.no': 'نہیں', 'shared.ok': 'ٹھیک ہے',
    'shared.loading': 'لوڈ ہو رہا ہے...', 'shared.saving': 'محفوظ ہو رہا ہے...', 'shared.sending': 'بھیجا جا رہا ہے...',
    'shared.success': 'کامیابی!', 'shared.error': 'ایک خرابی پیش آگئی', 'shared.tryAgain': 'دوبارہ کوشش کریں',
    'shared.comingSoon': 'جلد آرہا ہے', 'shared.free': 'مفت', 'shared.pro': 'پرو',
    'shared.ecosystem': 'ایکو سسٹم', 'shared.evolving': '🔄 مسلسل ارتقاء',
    'shared.jan':'جنوری','shared.feb':'فروری','shared.mar':'مارچ','shared.apr':'اپریل','shared.may':'مئی','shared.jun':'جون',
    'shared.jul':'جولائی','shared.aug':'اگست','shared.sep':'ستمبر','shared.oct':'اکتوبر','shared.nov':'نومبر','shared.dec':'دسمبر',
    'shared.sun':'اتوار','shared.mon':'پیر','shared.tue':'منگل','shared.wed':'بدھ','shared.thu':'جمعرات','shared.fri':'جمعہ','shared.sat':'ہفتہ',
  },

};
