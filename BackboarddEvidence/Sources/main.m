#import <UIKit/UIKit.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>

@interface EvidenceController : UIViewController <UIDocumentPickerDelegate>
@property(nonatomic, strong) UITextView *output;
@property(nonatomic, strong) NSMutableDictionary *analysis;
@property(nonatomic, strong) NSString *machine;
@property(nonatomic, strong) NSString *build;
@end

@implementation EvidenceController

- (NSString *)systemBuild {
    char buffer[128] = {0};
    size_t length = sizeof(buffer);
    if (sysctlbyname("kern.osversion", buffer, &length, NULL, 0) == 0)
        return [NSString stringWithUTF8String:buffer] ?: @"desconocido";
    return @"desconocido";
}

- (NSString *)modelIdentifier {
    struct utsname info = {0};
    if (uname(&info) == 0)
        return [NSString stringWithUTF8String:info.machine] ?: @"desconocido";
    return @"desconocido";
}

- (NSString *)stamp {
    return [NSISO8601DateFormatter new].stringFromDate([NSDate date]);
}

- (void)append:(NSString *)line {
    NSString *old = self.output.text ?: @"";
    self.output.text = [old stringByAppendingFormat:@"%@\n", line];
    if (self.output.text.length)
        [self.output scrollRangeToVisible:NSMakeRange(self.output.text.length-1, 1)];
}

- (UIButton *)action:(NSString *)caption selector:(SEL)selector {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.backgroundColor = UIColor.secondarySystemBackgroundColor;
    button.layer.cornerRadius = 12;
    [button setTitle:caption forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightSemibold];
    button.titleLabel.numberOfLines = 0;
    [button.heightAnchor constraintEqualToConstant:54].active = YES;
    [button addTarget:self action:selector forControlEvents:UIControlEventTouchUpInside];
    return button;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;
    self.machine = [self modelIdentifier];
    self.build = [self systemBuild];
    self.analysis = [@{
        @"tool": @"Backboardd Evidence Inspector v1",
        @"purpose": @"Local crash report review; no exploit payload",
        @"created": [self stamp],
        @"device": self.machine,
        @"iosVersion": UIDevice.currentDevice.systemVersion ?: @"?",
        @"iosBuild": self.build,
        @"source": @"Not imported",
        @"signals": @{},
        @"verdict": @"No crash report has been analyzed"
    } mutableCopy];

    UILabel *heading = [UILabel new];
    heading.text = @"Backboardd Evidence";
    heading.font = [UIFont systemFontOfSize:25 weight:UIFontWeightBold];
    heading.numberOfLines = 0;

    UILabel *subtitle = [UILabel new];
    subtitle.text = @"CVE-2026-112688 | Inspección local de registros. No ejecuta cargas de explotación ni modifica el kernel.";
    subtitle.numberOfLines = 0;
    subtitle.textColor = UIColor.secondaryLabelColor;
    subtitle.font = [UIFont systemFontOfSize:14];

    self.output = [UITextView new];
    self.output.editable = NO;
    self.output.selectable = YES;
    self.output.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    self.output.backgroundColor = UIColor.tertiarySystemBackgroundColor;
    self.output.layer.cornerRadius = 10;
    self.output.textContainerInset = UIEdgeInsetsMake(12, 10, 12, 10);

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[
        heading,subtitle,
        [self action:@"1. Revisar dispositivo" selector:@selector(checkDevice:)],
        [self action:@"2. Importar registro .ips / .txt / .json" selector:@selector(importReport:)],
        [self action:@"3. Exportar dictamen JSON" selector:@selector(exportReport:)],
        self.output
    ]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 12;
    stack.translatesAutoresizingMaskIntoConstraints = NO;

    UIScrollView *scroll = [UIScrollView new];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    [scroll addSubview:stack];
    [self.view addSubview:scroll];
    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [scroll.topAnchor constraintEqualToAnchor:safe.topAnchor],
        [scroll.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor],
        [scroll.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor],
        [scroll.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor],
        [stack.topAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.topAnchor constant:16],
        [stack.bottomAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.bottomAnchor constant:-16],
        [stack.leadingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.leadingAnchor constant:16],
        [stack.trailingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.trailingAnchor constant:-16],
        [stack.widthAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.widthAnchor constant:-32],
        [self.output.heightAnchor constraintEqualToConstant:380]
    ]];

    [self append:@"Backboardd Evidence Inspector v1"];
    [self append:@"Funciona completamente sin red."];
    [self append:@"No accede a backboardd, CoreMedia privado ni métodos del kernel."];
    [self append:@"Importá un crash report real desde Archivos para revisar sus indicadores."];
    [self checkDevice:nil];
}

- (void)checkDevice:(id)sender {
    NSString *system = UIDevice.currentDevice.systemVersion ?: @"?";
    [self append:[NSString stringWithFormat:@"DEVICE: %@ | iOS %@ | build %@",
                  self.machine,system,self.build]];
    [self append:@"FUENTE: el proyecto público documenta pruebas en otro modelo con iOS 27.1."];
    [self append:@"ALCANCE: número de versión anterior al parche no prueba que esta ruta sea explotable."];
    self.analysis[@"device"]=self.machine;
    self.analysis[@"iosVersion"]=system;
    self.analysis[@"iosBuild"]=self.build;
}

- (void)importReport:(id)sender {
    UIDocumentPickerViewController *picker =
      [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypeItem] asCopy:YES];
    picker.delegate=self;
    picker.allowsMultipleSelection=NO;
    [self presentViewController:picker animated:YES completion:nil];
}

- (BOOL)has:(NSString *)term in:(NSString *)text {
    return [text rangeOfString:term options:NSCaseInsensitiveSearch].location != NSNotFound;
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller
 didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url=urls.firstObject;
    if(!url)return;
    BOOL scoped=[url startAccessingSecurityScopedResource];
    @try {
        NSString *filename=url.lastPathComponent ?: @"sin_nombre";
        NSNumber *sizeNumber=nil;
        [url getResourceValue:&sizeNumber forKey:NSURLFileSizeKey error:NULL];
        if(sizeNumber && sizeNumber.unsignedLongLongValue>8ULL*1024ULL*1024ULL) {
            [self append:@"IMPORT: el archivo supera 8 MB; no se procesó."];
            return;
        }
        NSError *readError=nil;
        NSData *raw=[NSData dataWithContentsOfURL:url options:0 error:&readError];
        if(!raw) {
            [self append:[NSString stringWithFormat:@"IMPORT: error de lectura: %@",
                          readError.localizedDescription ?: @"desconocido"]];
            return;
        }
        if(raw.length>8ULL*1024ULL*1024ULL) {
            [self append:@"IMPORT: archivo demasiado grande; no se procesó."];
            return;
        }
        NSString *text=[[NSString alloc] initWithData:raw encoding:NSUTF8StringEncoding];
        if(!text)text=[[NSString alloc] initWithData:raw encoding:NSISOLatin1StringEncoding];
        if(!text) {
            [self append:@"IMPORT: formato no textual. Se acepta .ips/.txt/.json UTF-8."];
            return;
        }
        BOOL backboardd=[self has:@"backboardd" in:text];
        BOOL coremedia=[self has:@"CoreMedia" in:text];
        BOOL quartz=[self has:@"QuartzCore" in:text];
        BOOL pac=[self has:@"EXC_ARM_PAC_FAIL" in:text]||
                 [self has:@"PAC_EXCEPTION" in:text];
        BOOL sigValue=[self has:@"0x4141414141414141" in:text];
        BOOL crash=[self has:@"exception" in:text]||[self has:@"bug_type" in:text];
        NSMutableDictionary *signals=[@{
            @"mentionsBackboardd":@(backboardd),
            @"mentionsCoreMedia":@(coremedia),
            @"mentionsQuartzCore":@(quartz),
            @"mentionsPointerAuthenticationFailure":@(pac),
            @"mentions4141414141414141":@(sigValue),
            @"containsCrashIndicators":@(crash)
        } mutableCopy];
        NSString *verdict=@"No se encontraron indicadores suficientes en el texto.";
        if(backboardd && pac)
            verdict=@"El archivo contiene menciones de backboardd y PAC; requiere validación manual de contexto, proceso y pila.";
        else if(backboardd)
            verdict=@"El archivo menciona backboardd, pero no demuestra corrupción de memoria.";
        else if(pac)
            verdict=@"Hay indicadores PAC, pero no se confirmó que correspondan a backboardd.";
        self.analysis[@"source"]=filename;
        self.analysis[@"sourceSizeBytes"]=@(raw.length);
        self.analysis[@"reviewDate"]=[self stamp];
        self.analysis[@"signals"]=signals;
        self.analysis[@"verdict"]=verdict;
        self.analysis[@"disclaimer"]=@"Text matching only; this does not establish a CVE match, an exploit, kernelRW or a jailbreak.";
        [self append:[NSString stringWithFormat:@"IMPORT: %@ (%lu bytes)",
                      filename,(unsigned long)raw.length]];
        [self append:[NSString stringWithFormat:
                      @"SEÑALES: backboardd=%@ CoreMedia=%@ QuartzCore=%@ PAC=%@ patrón_A=%@",
                      backboardd?@"sí":@"no",coremedia?@"sí":@"no",
                      quartz?@"sí":@"no",pac?@"sí":@"no",sigValue?@"sí":@"no"]];
        [self append:[NSString stringWithFormat:@"DICTAMEN: %@",verdict]];
        [self append:@"PRIVACIDAD: el informe exportado NO incluye el registro original."];
    } @finally {
        if(scoped)[url stopAccessingSecurityScopedResource];
    }
}

- (void)exportReport:(id)sender {
    NSError *jsonError=nil;
    NSData *json=[NSJSONSerialization dataWithJSONObject:self.analysis
                        options:NSJSONWritingPrettyPrinted|NSJSONWritingSortedKeys error:&jsonError];
    if(!json) {
        [self append:[NSString stringWithFormat:@"EXPORT: %@",jsonError.localizedDescription]];
        return;
    }
    NSString *path=[NSTemporaryDirectory()
        stringByAppendingPathComponent:@"BackboarddEvidence-dictamen.json"];
    NSError *saveError=nil;
    if(![json writeToFile:path options:NSDataWritingAtomic error:&saveError]) {
        [self append:[NSString stringWithFormat:@"EXPORT: %@",saveError.localizedDescription]];
        return;
    }
    UIActivityViewController *share=[[UIActivityViewController alloc]
        initWithActivityItems:@[[NSURL fileURLWithPath:path]] applicationActivities:nil];
    share.popoverPresentationController.sourceView=self.view;
    [self presentViewController:share animated:YES completion:nil];
}
@end

@interface EvidenceApp : UIResponder <UIApplicationDelegate>
@property(nonatomic,strong) UIWindow *window;
@end

@implementation EvidenceApp
- (BOOL)application:(UIApplication *)application
 didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window=[[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController=[EvidenceController new];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc,char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc,argv,nil,NSStringFromClass([EvidenceApp class]));
    }
}
