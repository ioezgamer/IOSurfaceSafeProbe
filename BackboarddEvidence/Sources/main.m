#import <UIKit/UIKit.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>
#import <stdlib.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>


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
    return [[NSISO8601DateFormatter new] stringFromDate:[NSDate date]];
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
        @"tool": @"Backboardd Evidence Inspector v3",
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
    heading.text = @"Backboardd Evidence v3";
    heading.font = [UIFont systemFontOfSize:25 weight:UIFontWeightBold];
    heading.numberOfLines = 0;

    UILabel *subtitle = [UILabel new];
    subtitle.text = @"Comparación local de QuartzCore, CoreMedia e IOSurface para iOS 27.0. Solo lee información de los frameworks; no ejecuta exploit ni modifica el sistema.";
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
        [self action:@"3. Exportar informe y checkpoint" selector:@selector(exportReport:)],
        [self action:@"4. Prueba activa: cierre de esta app (SIGABRT)" selector:@selector(confirmSelfCrash:)],
        [self action:@"5. Comparar frameworks de mi iOS" selector:@selector(checkFrameworkUUIDs:)],
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

    [self append:@"Backboardd Evidence Inspector v3"];
    [self append:@"Funciona completamente sin red."];
    [self append:@"No accede a backboardd, CoreMedia privado ni métodos del kernel."];
    [self append:@"Prueba activa: cierre intencional solo de la aplicación, sin dañar la memoria del kernel."];
    [self showPreviousSelfCrash];
    [self append:@"NUEVO: botón 5 compara las UUID reales de QuartzCore, CoreMedia e IOSurface."];
    [self append:@"La comparación lee solo metadatos de bibliotecas públicas cargadas en esta app."];
    [self append:@"Podés importar el registro .ips real tras reabrirla."];
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



static NSString *FrameworkMachOUUID(NSString *component) {
    NSString *part=[NSString stringWithFormat:@"/%@.framework/%@",component,component];
    uint32_t imageCount=_dyld_image_count();
    for(uint32_t i=0;i<imageCount;i++) {
        const char *fullName=_dyld_get_image_name(i);
        if(!fullName)continue;
        NSString *name=[NSString stringWithUTF8String:fullName];
        if(![name containsString:part])continue;
        const struct mach_header *head=_dyld_get_image_header(i);
        if(!head || head->magic!=MH_MAGIC_64) return @"NO_MACHO64";
        const struct mach_header_64 *mach=(const struct mach_header_64 *)head;
        const uint8_t *cursor=(const uint8_t *)(mach+1);
        const uint8_t *limit=cursor+mach->sizeofcmds;
        for(uint32_t index=0;index<mach->ncmds;index++){
            if(cursor+sizeof(struct load_command)>limit)break;
            const struct load_command *cmd=(const struct load_command *)cursor;
            if(cmd->cmdsize<sizeof(struct load_command)||cursor+cmd->cmdsize>limit)break;
            if(cmd->cmd==LC_UUID && cmd->cmdsize>=sizeof(struct uuid_command)){
                const struct uuid_command *record=(const struct uuid_command *)cursor;
                NSUUID *uuid=[[NSUUID alloc] initWithUUIDBytes:record->uuid];
                return uuid.UUIDString?:@"UUID_NO_DISPONIBLE";
            }
            cursor+=cmd->cmdsize;
        }
        return @"UUID_NO_DISPONIBLE";
    }
    return @"NO_CARGADO";
}

- (void)checkFrameworkUUIDs:(id)sender {
    [self append:@"FRAMEWORKS: leyendo UUID Mach-O del proceso local. Sin IPC a backboardd."];
    NSString *expectedQuartz=@"21FA0104-F308-3BB3-8F3F-E9DE66F7CDEC";
    NSDictionary *libraries=@{
        @"QuartzCore":@"/System/Library/Frameworks/QuartzCore.framework/QuartzCore",
        @"CoreMedia":@"/System/Library/Frameworks/CoreMedia.framework/CoreMedia",
        @"IOSurface":@"/System/Library/Frameworks/IOSurface.framework/IOSurface"
    };
    NSMutableDictionary *observed=[NSMutableDictionary new];
    for(NSString *component in @[@"QuartzCore",@"CoreMedia",@"IOSurface"]){
        NSString *path=libraries[component];
        void *library=dlopen(path.UTF8String,RTLD_LAZY|RTLD_LOCAL);
        NSString *uuid=FrameworkMachOUUID(component);
        [self append:[NSString stringWithFormat:@"FRAMEWORKS: %@ UUID=%@",component,uuid]];
        observed[component]=uuid;
        if(library)dlclose(library);
    }
    NSString *actual=observed[@"QuartzCore"]?:@"NO_CARGADO";
    BOOL valid=[actual length]==36 && [actual containsString:@"-"];
    BOOL match=valid && [actual caseInsensitiveCompare:expectedQuartz]==NSOrderedSame;
    NSString *verdict=@"No se pudo leer QuartzCore; compatibilidad desconocida.";
    if(valid && match) verdict=@"UUID de QuartzCore coincide con la muestra pública de iOS 27.1. Eso no prueba explotación.";
    else if(valid) verdict=@"UUID de QuartzCore distinta a la muestra pública de iOS 27.1. La compatibilidad de cargas específicas no está demostrada.";
    NSDictionary *report=@{
        @"device":self.machine?:@"?",
        @"iosBuild":self.build?:@"?",
        @"iosVersion":UIDevice.currentDevice.systemVersion?:@"?",
        @"reference":@"0xjohnnydev/CVE-2026-112688-backboardd (public research, iOS 27.1)",
        @"expectedQuartzCoreUUID":expectedQuartz,
        @"loadedFrameworkUUIDs":observed,
        @"quartzCoreUUIDMatchesReference":@(match),
        @"verdict":verdict,
        @"checkedAt":[self stamp],
        @"limitations":@"Local UUID inspection only. Does not compare symbols, determine vulnerability, trigger a crash, or access backboardd/kernel."
    };
    self.analysis[@"frameworkCompatibility"]=report;
    [self append:[NSString stringWithFormat:@"FRAMEWORKS: %@",verdict]];
    [self append:@"FRAMEWORKS: exportá el informe JSON y compartí el bloque frameworkCompatibility."];
}

- (NSString *)selfCrashCheckpointPath {
    return [[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
        stringByAppendingPathComponent:@"BackboarddEvidence-SelfCrash-checkpoint.json"];
}

- (void)showPreviousSelfCrash {
    NSData *data=[NSData dataWithContentsOfFile:[self selfCrashCheckpointPath]];
    if(!data)return;
    NSDictionary *report=[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if(![report isKindOfClass:NSDictionary.class])return;
    [self append:[NSString stringWithFormat:
        @"SELF-CRASH: checkpoint anterior %@ estado=%@",
        report[@"run"]?:@"?",report[@"status"]?:@"?"]];
    [self append:@"SELF-CRASH: un checkpoint previo no demuestra la causa del cierre; verificá el .ips de iOS."];
    self.analysis[@"selfCrashCheckpoint"]=report;
}

- (void)confirmSelfCrash:(id)sender {
    UIAlertController *alert=[UIAlertController
        alertControllerWithTitle:@"Cerrar esta aplicación"
        message:@"Esta prueba guarda un checkpoint y finaliza voluntariamente esta misma app con SIGABRT. El proceso se cerrará. No utiliza errores de memoria, no toca backboardd ni el kernel y no es una prueba de CVE-2026-112688."
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancelar"
        style:UIAlertActionStyleCancel handler:nil]];
    __weak typeof(self) weakSelf=self;
    [alert addAction:[UIAlertAction actionWithTitle:@"Ejecutar cierre local"
        style:UIAlertActionStyleDestructive handler:^(__unused UIAlertAction *a){
            [weakSelf runSelfCrash];
        }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)runSelfCrash {
    NSString *run=NSUUID.UUID.UUIDString;
    NSDictionary *checkpoint=@{
        @"tool":@"Backboardd Evidence Inspector v2",
        @"run":run,@"status":@"CHECKPOINT_BEFORE_TERMINATION",
        @"test":@"APPLICATION_SELF_TERMINATION_SIGABRT",
        @"expectedResult":@"EXC_CRASH / SIGABRT in this app only",
        @"device":self.machine?:@"?",
        @"iosBuild":self.build?:@"?",
        @"iosVersion":UIDevice.currentDevice.systemVersion?:@"?",
        @"timestamp":[self stamp],
        @"memoryCorruptionAttempted":@NO,
        @"kernelAccessAttempted":@NO,
        @"otherProcessTouched":@NO
    };
    NSError *err=nil;
    NSData *data=[NSJSONSerialization dataWithJSONObject:checkpoint
                            options:NSJSONWritingPrettyPrinted error:&err];
    if(!data || ![data writeToFile:[self selfCrashCheckpointPath]
                          options:NSDataWritingAtomic error:&err]) {
        [self append:[NSString stringWithFormat:
            @"SELF-CRASH: no se guardó checkpoint; prueba cancelada: %@",
            err.localizedDescription?:@"error desconocido"]];
        return;
    }
    [self append:[NSString stringWithFormat:
        @"SELF-CRASH: checkpoint guardado para %@. Cerrando esta app.",run]];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
        abort();
    });
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
    NSMutableArray *items=[NSMutableArray arrayWithObject:[NSURL fileURLWithPath:path]];
    NSString *checkpointPath=[self selfCrashCheckpointPath];
    if([[NSFileManager defaultManager] fileExistsAtPath:checkpointPath])
        [items addObject:[NSURL fileURLWithPath:checkpointPath]];
    UIActivityViewController *share=[[UIActivityViewController alloc]
        initWithActivityItems:items applicationActivities:nil];
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
